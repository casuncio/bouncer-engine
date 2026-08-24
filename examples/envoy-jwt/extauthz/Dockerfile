# syntax=docker/dockerfile:1.7

# ---- build stage ----
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/bouncer-extauthz ./examples/envoy-jwt/extauthz

# ---- runtime stage ----
# distroless/static: ~2MB, no shell, no package manager, no glibc. The adapter
# is a static Go binary listening on a high port, so the nonroot user
# (uid 65532) runs it without privilege.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/bouncer-extauthz /bouncer-extauthz

# ext_authz gRPC service.
EXPOSE 9191

USER nonroot:nonroot

ENTRYPOINT ["/bouncer-extauthz"]
