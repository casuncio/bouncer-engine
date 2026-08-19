#!/usr/bin/env bash

echo "========================================"
echo " Running Bouncer Engine Benchmarks via Docker"
echo "========================================"
echo "Simulating strict limits: 1 vCPU / 1 GB RAM..."

# Run the benchmark inside an ephemeral Docker container
docker run --rm \
  --cpus="1.0" \
  --memory="1g" \
  -v "$(pwd)":/app \
  -w /app \
  golang:1.26-alpine \
  go test ./internal/engine/ -bench=. -benchmem -cpu=1 -memprofile=mem.out

echo "========================================"
echo "✅ Done! Memory profile saved to mem.out"
echo "To view the memory profile, run:"
echo "go tool pprof -http=:8080 mem.out"