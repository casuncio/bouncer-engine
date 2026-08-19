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

## Performance Benchmarks (Baseline)

Bouncer Engine is strictly engineered for high-throughput, low-latency authorization checks. The following benchmarks represent our **pre-optimization baseline** running on a single CPU thread (`-cpu=1`) to simulate strict production container constraints.

### 1. Project Targets
* **Evaluation Latency:** < 2 ms (p99) for in-memory decision evaluations.
* **Throughput:** > 10,000 RPS per instance on 1 vCPU / 1 GB RAM.

### 2. Baseline Results
*Hardware: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (Constrained to 1 vCPU)*

| Component / Operator | Execution Speed (ns/op) | Memory Allocated (B/op) | Heap Allocations (allocs/op) |
| :--- | :--- | :--- | :--- |
| **Full Engine Evaluation** | 6,734 | 7,096 | 84 |
| **Operator: EQUALS** | 558.6 | 496 | 6 |
| **Operator: CONTAINS_ALL**| 572.1 | 496 | 6 |
| **Operator: CONTAINS_ANY**| 537.8 | 496 | 6 |
| **Operator: BETWEEN** | 543.5 | 504 | 6 |
| **Operator: IN_CIDR** | 701.3 | 576 | 10 |
| **Operator: REGEX** | 5,258 | 6,840 | 70 |

### 3. Engineering Analysis
The core evaluation logic is highly performant. A full ABAC policy evaluation currently completes in **~0.0067 milliseconds**, which easily beats the < 2 ms latency budget. 

**Next Steps (Zero-Allocation Parsing):** 
While the execution speed is exceptional, the granular benchmarks reveal that the `REGEX` operator and the overall evaluation pipeline generate a high number of heap allocations (70 and 84 `allocs/op` respectively). To meet our goal of zero-allocation parsing where possible, the next phase of development will focus on eliminating these heap escapes to prevent Garbage Collection (GC) pauses under heavy load.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

