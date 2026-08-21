.PHONY: all gen test bench

# Default target
all: gen test build

## gen: Generate Go stubs from Protobuf files using buf
gen:
	@echo "==> Generating Protobuf stubs via buf..."
	buf generate api

## test: Run unit tests with the race detector and coverage
test:
	@echo "==> Running Go unit tests..."
	go test -v -race -cover ./...

## bench: Run performance benchmarks for the core evaluation engine
bench:
	@echo "==> Running Engine Benchmarks (1 vCPU constraint)..."
	go test ./internal/engine/ -bench=. -benchmem -cpu=1

## build: Compile the Bouncer Engine binary
build:
	@echo "==> Building Bouncer Engine..."
	go build -ldflags="-s -w" -o bin/bouncer-engine ./cmd/bouncer-engine/main.go