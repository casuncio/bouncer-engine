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
* **Interface:** gRPC / Protocol Buffers (Planned)
* **Data Model:** JSON Schema-backed policy definitions

### Directory Structure
* `api/` - API contracts, JSON Schemas, and Protobuf definitions.
* `cmd/` - Executable entry points.
* `internal/` - Private application logic (Policy Engine, Datastore, Audit Pipeline).
* `pkg/` - Public libraries and generated client stubs.

## 🚀 Performance Benchmarks (Optimized)

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

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

