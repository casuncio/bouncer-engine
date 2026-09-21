# ---- build stage ----
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache module downloads independently of source changes.
# Plain layer cache so this builds without BuildKit (see repo Dockerfile).
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/bouncer-pep ./examples/httpbin/pep

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/bouncer-pep /bouncer-pep

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/bouncer-pep"]
