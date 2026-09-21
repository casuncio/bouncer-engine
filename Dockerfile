# ---- build stage ----
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes.
# Plain layer cache (COPY go.mod/go.sum before the tree) so this builds with
# the classic builder as well as BuildKit. Cache mounts require BuildKit,
# which is not available everywhere docker compose runs.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a fully static binary, which pairs with
# distroless/static (no glibc). -ldflags="-s -w" strips debug info to shrink
# the image, matching the Makefile build flags.
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/bouncer-engine ./cmd/bouncer-engine

# ---- runtime stage ----
# distroless/static: ~2MB, no shell, no package manager, no glibc. The engine
# is a static Go binary that listens on high ports (>1024), so the nonroot
# user (uid 65532) can run it without privilege.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/bouncer-engine /bouncer-engine

# gRPC API + Prometheus /metrics.
EXPOSE 50051 9090

USER nonroot:nonroot

ENTRYPOINT ["/bouncer-engine"]
