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

## Performance Benchmarks (Optimized)

Bouncer Engine is strictly engineered for high-throughput, low-latency authorization checks. The following benchmarks represent our **optimized, zero-allocation** evaluation path running on a single CPU thread (`-cpu=1`) to simulate strict production container constraints.

### 1. Project Targets
* **Evaluation Latency:** < 2 ms (p99) for in-memory decision evaluations.
* **Throughput:** > 10,000 RPS per instance on 1 vCPU / 1 GB RAM[cite: 6].

### 2. Benchmark Results
*Hardware: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (Constrained to 1 vCPU / 1 GB RAM)*

| Component / Operator | Execution Speed (ns/op) | Memory Allocated (B/op) | Heap Allocations (allocs/op) |
| :--- | :--- | :--- | :--- |
| **Full Engine Evaluation** | 851.8 | 0 | 0 |
| **Operator: EQUALS** | 159.8 | 0 | 0 |
| **Operator: CONTAINS_ALL** | 180.1 | 0 | 0 |
| **Operator: CONTAINS_ANY** | 144.6 | 0 | 0 |
| **Operator: BETWEEN** | 144.3 | 0 | 0 |
| **Operator: IN_CIDR** | 178.0 | 0 | 0 |
| **Operator: REGEX** | 305.8 | 0 | 0 |

### 3. Engineering Analysis
The core evaluation logic achieves **zero-allocation parsing**, meaning the Garbage Collector (GC) is not triggered during high-speed access checks. 

A full ABAC policy evaluation completes in **~0.00085 milliseconds**, which easily obliterates the < 2 ms latency budget[cite: 6]. At this speed, a single CPU core can theoretically process over 1.1 million authorization evaluations per second, providing immense headroom for network and gRPC I/O overhead.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

