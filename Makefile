SHELL := /usr/bin/env bash

.PHONY: all gen test bench build loadtest loadtest-docker loadtest-smoke engine-start engine-stop run need-go need-buf need-k6 need-docker

# Default target
all: gen test build

# --- Engine settings ---------------------------------------------------------
ENGINE_BIN            := bin/bouncer-engine
ENGINE_PID            := engine.pid
ENGINE_LOG            := engine.log
ENGINE_ADDR           ?= localhost:50051
# number of 0.5s readiness polls (30 => ~15s)
ENGINE_READY_TIMEOUT  ?= 30
K6_OUT                ?=

# BOUNCER_* knobs are read by loadtest/checkaccess.js as k6 environment.
# Export them so the local k6 binary and the grafana/k6 container both inherit them.
export BOUNCER_TARGET        ?= $(ENGINE_ADDR)
export BOUNCER_BASELINE_RPS
export BOUNCER_STRESS_RPS
export BOUNCER_SKIP_BASELINE
export BOUNCER_SKIP_STRESS

# Bash /dev/tcp wants host/port as separate path segments: host:port -> host/port.
tcp_addr              = $(subst :,/,$(ENGINE_ADDR))

# k6 invocations (overridable per-target / via environment).
# Docker forwards the BOUNCER_* knobs via -e so the container honors the same
# profile settings as the local k6 run.
K6_RUN_LOCAL  := k6 run loadtest/checkaccess.js
K6_RUN_DOCKER := docker run --rm --network host \
	-e BOUNCER_TARGET -e BOUNCER_BASELINE_RPS -e BOUNCER_STRESS_RPS \
	-e BOUNCER_SKIP_BASELINE -e BOUNCER_SKIP_STRESS \
	-v "$(PWD)":/src -w /src grafana/k6 run /src/loadtest/checkaccess.js

# --- Tool checks ------------------------------------------------------------
# Per-target guards: fail fast with a clear message if a required binary is
# missing from PATH. Silent on success, so they add no noise to normal runs.
need-go:
	@command -v go >/dev/null || { echo "::error::'go' not found in PATH (install Go)"; exit 1; }
need-buf:
	@command -v buf >/dev/null || { echo "::error::'buf' not found in PATH (install bufbuild/buf)"; exit 1; }
need-k6:
	@command -v k6 >/dev/null || { echo "::error::'k6' not found in PATH (install k6)"; exit 1; }
need-docker:
	@command -v docker >/dev/null || { echo "::error::'docker' not found in PATH (install Docker)"; exit 1; }

## gen: Generate Go stubs from Protobuf files using buf
gen: need-buf
	@echo "==> Generating Protobuf stubs via buf..."
	buf generate api

## test: Run unit tests with the race detector and coverage
test: need-go
	@echo "==> Running Go unit tests..."
	go test -v -race -cover ./...

## bench: Run performance benchmarks for the core evaluation engine
bench: need-go
	@echo "==> Running Engine Benchmarks (1 vCPU constraint)..."
	go test ./internal/engine/ -bench=. -benchmem -cpu=1

## build: Compile the Bouncer Engine binary
build: need-go
	@echo "==> Building Bouncer Engine..."
	go build -ldflags="-s -w" -o bin/bouncer-engine ./cmd/bouncer-engine/main.go

# --- Engine lifecycle --------------------------------------------------------
# Block until the engine accepts TCP connections on $(ENGINE_ADDR).
# Exits non-zero if it doesn't come up within $(ENGINE_READY_TIMEOUT) polls.
define wait_for_engine
	for _ in $$(seq 1 $(ENGINE_READY_TIMEOUT)); do \
		if (echo > /dev/tcp/$(tcp_addr)) 2>/dev/null; then \
			echo "engine ready on $(ENGINE_ADDR)"; break; \
		fi; \
		sleep 0.5; \
	done; \
	if ! (echo > /dev/tcp/$(tcp_addr)) 2>/dev/null; then \
		echo "::error::engine not ready on $(ENGINE_ADDR) after $$(( ($(ENGINE_READY_TIMEOUT) + 1) / 2 ))s"; \
		cat $(ENGINE_LOG) 2>/dev/null; exit 1; \
	fi
endef

# start_engine: idempotent — if $(ENGINE_ADDR) already accepts connections, no-op.
# Sets shell var __started=1 when it launched the engine, 0 otherwise, so callers
# can gate cleanup (e.g. an EXIT trap) on whether they actually started it.
define start_engine
	__started=0; \
	if (echo > /dev/tcp/$(tcp_addr)) 2>/dev/null; then \
		echo "engine already running on $(ENGINE_ADDR)"; \
	else \
		echo "==> Starting bouncer engine (log -> $(ENGINE_LOG))..."; \
		./$(ENGINE_BIN) > $(ENGINE_LOG) 2>&1 & echo $$! > $(ENGINE_PID); \
		__started=1; \
		echo "==> Waiting for engine on $(ENGINE_ADDR)..."; \
		$(wait_for_engine); \
	fi
endef

# stop_engine: kept on one line so it expands cleanly inside a single-quoted
# EXIT trap. Tolerant of a missing PID file (engine started externally or never).
define stop_engine
	echo "==> Stopping bouncer engine..."; if [ -f $(ENGINE_PID) ]; then kill "$$(cat $(ENGINE_PID))" 2>/dev/null || true; rm -f $(ENGINE_PID); fi
endef

## engine-start: Build and launch the engine in the background, wait for :50051
engine-start: build
	@$(start_engine)

## engine-stop: Stop the engine started by `engine-start`
engine-stop:
	@$(stop_engine)

## run: Build and run the engine in the foreground (Ctrl-C to stop)
run: build
	@echo "==> Running bouncer engine in foreground (Ctrl-C to stop)..."
	./$(ENGINE_BIN)

# --- Load tests --------------------------------------------------------------
# Full lifecycle load test. $(K6_RUN) selects the k6 invocation (local vs docker).
# Reuses an already-running engine; otherwise starts one and stops it on exit.
define run_loadtest
	@set -e; \
	trap 'if [ "$${__started:-0}" = "1" ]; then $(stop_engine); fi' EXIT; \
	$(start_engine); \
	echo "==> Seeding test policies..."; \
	go run ./loadtest/seed; \
	echo "==> Running k6 load test..."; \
	$(K6_RUN) $(if $(K6_OUT),--out json=$(K6_OUT),); \
	exit 0
endef

## loadtest: Build, start engine, seed policies, run k6 (local), stop engine
loadtest: K6_RUN := $(K6_RUN_LOCAL)
loadtest: build need-k6
	$(run_loadtest)

## loadtest-docker: Same as `loadtest` but runs k6 via the grafana/k6 Docker image
loadtest-docker: K6_RUN := $(K6_RUN_DOCKER)
loadtest-docker: build need-docker
	$(run_loadtest)

## loadtest-smoke: Quick baseline-only smoke test (50 RPS, no stress scenario)
loadtest-smoke:
	@echo "==> Smoke profile (baseline 50 RPS, stress skipped)..."
	@BOUNCER_BASELINE_RPS=50 BOUNCER_SKIP_STRESS=true $(MAKE) loadtest
