# 🛡️ Bouncer Engine

> 🚧 🏗️ **Status: Active Development (Pre-Alpha)** 🏗️ 🚧  
> *Bouncer Engine is currently a work in progress. The core evaluation engine is being built, and API contracts (gRPC/REST) are subject to change. It is not yet ready for production use.*

Bouncer Engine is an open-source, high-performance Attribute-Based Access Control (ABAC) authorization engine written in Go. 

It acts as a centralized Policy Decision Point (PDP) for microservices, evaluating dynamic requests against a set of rules to enforce Zero-Trust architectures and granular access controls.

## Core Concepts

Unlike standard Role-Based Access Control (RBAC) which relies on static group assignments, Bouncer evaluates requests dynamically based on three categories of attributes:
* **Principal Attributes:** Who is making the request? (e.g., roles, clearance level, department)
* **Resource Attributes:** What is being accessed? (e.g., environment, data sensitivity, owner)
* **Environment Attributes:** What is the context? (e.g., IP address, time of day)

## Architecture

* **Language:** Go 1.26
* **Interface:** gRPC / Protocol Buffers
* **Data Model:** JSON Schema-backed policy definitions
* **Observability:** Prometheus metrics + auto-provisioned Grafana dashboard

### Directory Structure
* `api/` - API contracts, JSON Schemas, and Protobuf definitions.
* `cmd/` - Executable entry points (`bouncer-engine` server, `mock-client` demo client).
* `cmd/` - Executable entry points.
* `internal/` - Private application logic (Policy Engine, Datastore, Audit Pipeline, Metrics).
* `pkg/` - Public libraries and generated client stubs.
* `deploy/` - Docker Compose observability stack (engine + Prometheus + Grafana).
* `Dockerfile` - Multi-stage build producing a distroless runtime image for the engine.

## Getting Started

### Prerequisites
* **Go 1.26+** to build from source, **or** **Docker + Docker Compose v2** to run the containerized stack.

### Run locally (binary)
```bash
make build            # produces bin/bouncer-engine
./bin/bouncer-engine  # serves gRPC on :50051, /metrics on :9090
```

### Run the full stack via Docker
One command builds the engine image and brings up the engine, Prometheus, and Grafana on a shared bridge network:
```bash
docker compose -f deploy/observability/docker-compose.yml up -d --build
```

| Service        | Address                          | Notes                                            |
| :---           | :---                             | :---                                             |
| Bouncer Engine | `localhost:50051` (gRPC)         | Raw metrics at `http://localhost:9090/metrics`   |
| Prometheus     | `http://localhost:9091`          | Scrapes the engine every 15s                     |
| Grafana        | `http://localhost:3000`          | `admin` / `admin`                                |

The Grafana "Bouncer Engine" dashboard and Prometheus datasource are auto-provisioned on first boot — no manual UI import required.

## Examples

End-to-end demos of Bouncer Engine acting as a **Policy Decision Point (PDP)** behind a Policy Enforcement Point (PEP):

* [examples/httpbin](examples/httpbin) — the "hello world": a hand-written Go reverse proxy (the PEP) in front of [httpbin](https://github.com/kong/httpbin), calling `CheckAccess` on every request. Three containers, no external dependencies.
* [examples/envoy-jwt](examples/envoy-jwt) — the production-shaped step up: **Envoy** verifies JWTs issued by **Dex** (OIDC) at the edge and enforces the engine's ABAC decisions via Envoy's external authorization filter, giving a clean authn ↔ authz split.

## Testing

### Unit tests
```bash
make test   # go test -v -race -cover ./...
```

### Core engine benchmarks
```bash
make bench  # engine benchmarks, constrained to 1 vCPU
```

### Sample traffic
```bash
go run ./cmd/mock-client   # streams a policy and performs one CheckAccess
```

### Load testing (k6)
A k6 gRPC load test lives in `loadtest/`. The `make loadtest` target starts Redis when `REDIS_ADDR` is not already accepting connections (`redis:7-alpine` via Docker), starts the engine, runs a Go policy seeder (`loadtest/seed/`) that publishes three test policies to the Redis stream, then launches k6 against `CheckAccess` with a mix of allow/deny fixtures exercising every operator (`CONTAINS_ANY`, `IN_CIDR`, `BETWEEN`, `EQUALS`, explicit-deny, implicit-deny). k6 must be installed locally; Docker is required only when Redis is not already running. An already-listening Redis or engine is reused and left running.

```bash
make loadtest          # starts redis + engine, seeds policies, runs k6
make loadtest-docker   # same, but runs k6 via the grafana/k6 image
make loadtest-smoke    # quick 50-RPS baseline-only check
```

The run reports **p50 / p90 / p95 / p99** for both end-to-end gRPC latency (`grpc_req_duration`) and engine-reported evaluation time (`engine_eval_time_ns`, the same value the Prometheus histogram captures). Thresholds that fail the run:

| Metric                  | Threshold        | Meaning                              |
| :---                    | :---             | :---                                 |
| `grpc_req_duration`     | p(99) < 10 ms    | End-to-end gRPC round-trip           |
| `engine_eval_time_ns`   | p(99) < 2 ms     | Engine's own evaluation (README SLA) |
| `checks`                | rate > 99.5 %    | Status + decision-correctness checks |

**Configuration via environment variables:**

| Variable                 | Default             | Description                                  |
| :---                     | :---                | :---                                         |
| `BOUNCER_TARGET`         | `localhost:50051`   | Engine gRPC address (used by both seeder and k6) |
| `REDIS_ADDR`             | `127.0.0.1:6379`    | Redis address for policy seeding. `make loadtest` starts Redis here when the port is closed |
| `BOUNCER_BASELINE_RPS`   | `1000`              | Target RPS for the baseline scenario         |
| `BOUNCER_STRESS_RPS`     | `10000`             | Target RPS for the stress scenario           |
| `BOUNCER_SKIP_BASELINE`  | `false`             | Set `true` to run only the stress scenario   |
| `BOUNCER_SKIP_STRESS`    | `false`             | Set `true` to run only the baseline scenario |

Example: stress-only at 5 000 RPS against a remote engine:
```bash
BOUNCER_TARGET=engine.internal:50051 BOUNCER_STRESS_RPS=5000 \
  BOUNCER_SKIP_BASELINE=true k6 run loadtest/checkaccess.js
```

#### CI integration
The load test runs automatically in GitHub Actions via `.github/workflows/loadtest.yml`:

| Trigger            | Profile  | Purpose                              |
| :---               | :---     | :---                                 |
| `pull_request`     | smoke    | Fast PR gate (~2 min, 50 RPS)        |
| nightly `schedule` | baseline | Regression signal (1 000 RPS, 1 min) |
| `workflow_dispatch`| chosen   | On-demand smoke / baseline / full     |

The workflow provides Redis as a service container, then `make loadtest` builds the engine, starts it in the background, waits for `:50051` readiness, seeds policies, runs k6, and uploads `loadtest-results.json` + `engine.log` as artifacts. Because that service is already listening, the Make target does not start a second Redis. A threshold breach (E2E p99 ≥ 10 ms, engine eval p99 ≥ 2 ms, or check failures) fails the run. The manual dispatch exposes `profile`, `baseline_rps`, and `stress_rps` inputs.

## Performance Benchmarks (Optimized)

Bouncer Engine is strictly engineered for high-throughput, low-latency authorization checks. The following benchmarks represent our **optimized, zero-allocation** evaluation path running on a single CPU thread (`-cpu=1`) to simulate strict production container constraints.

### 1. Project Targets
* **Evaluation Latency:** < 2 ms (p99) for in-memory decision evaluations.
* **Throughput:** > 10,000 RPS per instance on 1 vCPU / 1 GB RAM.
* **Memory Efficiency:** 0 heap allocations on the critical evaluation path (`0 allocs/op`).

### 2. Benchmark Results
*Hardware: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (Constrained to 1 vCPU / 1 GB RAM via Docker)*

| Component / Operator | Execution Speed (ns/op) | Memory Allocated (B/op) | Heap Allocations (allocs/op) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Full Engine Evaluation** | **1,495.0** | **0** | **0** | 🟢 Passing |
| **Operator: EQUALS** | 260.1 | 0 | 0 | 🟢 Passing |
| **Operator: CONTAINS_ALL** | 219.8 | 0 | 0 | 🟢 Passing |
| **Operator: CONTAINS_ANY** | 238.4 | 0 | 0 | 🟢 Passing |
| **Operator: BETWEEN** | 201.0 | 0 | 0 | 🟢 Passing |
| **Operator: IN_CIDR** | 282.8 | 0 | 0 | 🟢 Passing |
| **Operator: REGEX** | 422.8 | 0 | 0 | 🟢 Passing |

### 3. Engineering Analysis
* **Zero-Allocation Parsing:** The evaluation engine achieves **0 allocs/op** and **0 B/op** across all operators. Stack-based string lookups (`strings.Cut`), immutable IP structures (`net/netip`), and load-time regex pre-compilation eliminate heap escapes entirely.
* **Sub-Millisecond Latency:** A complete multi-condition policy evaluation finishes in **~0.0015 ms**, safely clearing the < 2 ms latency threshold.
* **Throughput Headroom:** With an average execution speed of 1,495 ns/op, a single constrained CPU core can theoretically sustain over **668,000 evaluations per second**, easily exceeding the > 10,000 RPS requirement while leaving ample headroom for gRPC networking and asynchronous audit logging.

## Observability

Bouncer Engine exposes Prometheus metrics via a gRPC unary interceptor in `internal/metrics`. Instrumentation lives in the gRPC seam, so the zero-allocation evaluation path in `internal/engine` stays untouched (benchmarks still report `0 allocs/op`).

### Metrics

| Metric                              | Type      | Labels   | Description                                                            |
| :---                                | :---      | :---     | :---                                                                   |
| `authz_evaluations_total`           | Counter   | `access` | Total evaluations, labelled `allow` or `deny`.                         |
| `authz_evaluation_duration_seconds` | Histogram | —        | Engine-reported evaluation time (from `evaluation_time_ns`), seconds.  |
| `authz_policy_count`                | Gauge     | —        | Active policies in the in-memory store (allow + deny tables).          |

The policy-count gauge is **pull-based** — recomputed on every Prometheus scrape — so policy mutations pay nothing on the hot path. The evaluation counter is curried into fixed `allow`/`deny` child counters at startup, making each increment a single atomic add with zero label-map allocations.

### Grafana dashboard
The provisioned dashboard (`deploy/observability/grafana/dashboards/bouncer-engine.json`) ships four panels:

* **Evaluations / sec** — `sum by (access) (rate(authz_evaluations_total[1m]))`, allow vs deny.
* **Deny ratio (5m)** — deny rate / total rate, with green / amber / red thresholds.
* **Evaluation latency** — p50 / p95 / p99 from the histogram, in milliseconds.
* **Active policies** — `authz_policy_count`.

To tear the stack down (preserving data volumes): `docker compose -f deploy/observability/docker-compose.yml down`. Add `-v` to wipe the Prometheus and Grafana data volumes.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

