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

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

