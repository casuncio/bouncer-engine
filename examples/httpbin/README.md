# bouncer-engine HelloWorld — safeguarding httpbin

A minimal, end-to-end demo of [bouncer-engine](../../README.md) acting as a
**Policy Decision Point (PDP)** in front of a real HTTP service.

A small reverse proxy — the **Policy Enforcement Point (PEP)** — sits in front
of [httpbin](https://github.com/kong/httpbin). On every request it asks
bouncer-engine `CheckAccess` whether the caller may proceed, forwards the
request to httpbin only on `allow`, and returns `403` on `deny`.

```
   client (curl)            bouncer-pep (PEP)              httpbin
        |                         |                          |
        |--- HTTP :8080 --------->|                          |
        |                         |--- gRPC CheckAccess ---->| bouncer-engine (PDP)
        |                         |<----- allowed? ----------|
        |                         |                          |
        |                         |--- proxy (allow) ------->|
        |                         |<---- 200 httpbin --------|
        |<---- 200 / 403 ---------|                          |
```

## Why this demo

bouncer-engine is a **PDP**: it decides, it does not enforce. To *safeguard* a
service you also need a **PEP** that intercepts traffic and asks the PDP. This
example shows that split concretely, with three containers and zero external
dependencies beyond Docker.

## Architecture

| Container            | Role | Image / build              | Listens on (in-compose) | Host port |
| :---                 | :--- | :---                       | :---                    | :---      |
| `bouncer-engine`     | PDP  | built from repo `Dockerfile` | `:50051` gRPC, `:9090` metrics | `50051`, `9090` |
| `bouncer-pep`        | PEP  | built from `examples/httpbin/pep/Dockerfile` | `:8080` HTTP | `8080` |
| `httpbin`            | protected service | `kong/httpbin:latest` | `:80` (internal only) | *not published* |

All three live on one user-defined bridge network (`bouncer-demo-net`), so they
address each other by service name — no host networking, no `host.docker.internal`.
httpbin is intentionally **not** published to the host: the only way in is through
the PEP on `:8080`, which is the whole point.

## File layout

```
examples/httpbin/
├─ README.md                       # this file
├─ docker-compose.yml              # 3 services on bouncer-demo-net
├─ policies/                       # loaded into the engine by the PEP at startup
│  ├─ pol-deny-blocked-read.json   # DENY httpbin/READ  role CONTAINS_ANY ["blocked"]
│  ├─ pol-allow-staff-read.json    # ALLOW httpbin/READ  role CONTAINS_ANY ["admin","user"]
│  └─ pol-allow-admin-write.json   # ALLOW httpbin/WRITE role EQUALS ["admin"]
└─ pep/
   ├─ main.go                      # reverse proxy + gRPC CheckAccess + policy seeding
   └─ Dockerfile                   # multi-stage, distroless runtime
```

## How the PEP works

1. **Startup** — dials `bouncer-engine:50051` over gRPC (with retry/backoff, since
   `depends_on` only waits for the container to *start*, not for gRPC to *listen*),
   opens the `StreamPolicyUpdates` client stream, pushes every `*.json` file in
   `/policies` as an `UPSERT`, and closes the stream. The engine's in-memory store
   is now seeded. Then it serves HTTP on `:8080`.
2. **Per request** — builds a `CheckAccessRequest` from the inbound HTTP request:
   - `principal_id` ← `X-User` header (default `anonymous`)
   - `principal.role` ← every `X-Role` header value (multi-valued ABAC attribute)
   - `action` ← HTTP method: `GET`/`HEAD`/`OPTIONS` → `READ`, everything else → `WRITE`
   - `resource_type` = `httpbin`, `resource_id` = request path
   - `environment.ip_address` ← the caller's `RemoteAddr` host (wired so a CIDR
     policy would work; not used by the default policies)
3. **Decision** — calls `CheckAccess`. On `allow`, `httputil.ReverseProxy` forwards
   to `http://httpbin`. On `deny`, returns `403` JSON with the engine's `reason`,
   `matched_policy_id`, and `evaluation_time_ns`. If the engine is unreachable
   mid-request, it returns `503` (fail-closed).

The engine is **deny-by-default**: a request that matches no policy is denied.

## Prerequisites

* Docker + Docker Compose v2 (`docker compose version` should print a v2 number).

No Go toolchain is required to *run* the demo — both Go services are built inside
multi-stage Docker images.

## Run it

From the repo root:

```bash
docker compose -f examples/httpbin/docker-compose.yml up -d --build
```

First run takes a couple of minutes (builds two Go images). Subsequent runs reuse
the build cache. Check readiness:

```bash
docker compose -f examples/httpbin/docker-compose.yml logs bouncer-pep | grep "policies seeded"
# -> {"msg":"policies seeded into bouncer engine","count":3,"active_policy_count":3,...}

# Cross-check the live policy gauge (should be 3):
curl -s localhost:9090/metrics | grep '^authz_policy_count '
# -> authz_policy_count 3
```

The `active_policy_count` in the PEP log comes straight from the engine's
`StreamPolicyUpdates` acknowledgement, which reports the live store count after
the session's upserts have been applied.

## Walkthrough

The PEP maps `X-User`/`X-Role` headers to ABAC principal attributes, so you can
test any identity with `curl`. (`-s -o /dev/null -w "%{http_code}\n"` prints just
the status code; drop it to see httpbin's echo body on allowed calls.)

```bash
# 1. Staff READ is allowed.
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: alice" -H "X-Role: admin" localhost:8080/get
# -> 200
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: bob"   -H "X-Role: user"  localhost:8080/get
# -> 200

# 2. Explicit DENY: a blocked principal is denied even though they also have a staff role.
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: mallory" -H "X-Role: blocked" localhost:8080/get
# -> 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: eve" -H "X-Role: admin" -H "X-Role: blocked" localhost:8080/get
# -> 403   (deny-overrides: eve has BOTH admin and blocked)

# 3. Default DENY: no role at all -> no policy matches.
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/get
# -> 403

# 4. WRITE requires the role set to be exactly ["admin"] (EQUALS compares the full set).
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: bob"   -H "X-Role: user"  -X POST localhost:8080/post
# -> 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-User: alice" -H "X-Role: admin" -X POST localhost:8080/post
# -> 200
```

Inspect a deny body to see the engine's reason and matched policy:

```bash
curl -s -H "X-User: mallory" -H "X-Role: blocked" localhost:8080/get
# {
#   "allowed": false,
#   "evaluation_time_ns": 5941,
#   "matched_policy_id": "pol-deny-blocked-read",
#   "reason": "Explicit Deny: Matched deny policy"
# }
```

And an allowed call passes straight through to httpbin, which echoes the request
(headers are forwarded verbatim — a production PEP would strip identity headers
before proxying; this demo keeps them so you can see the round-trip):

```bash
curl -s -H "X-User: alice" -H "X-Role: admin" localhost:8080/get | jq '.headers'
```

## Observe the engine

The PEP logs every decision; the engine exposes Prometheus metrics:

```bash
# PEP decision log (one line per request):
docker compose -f examples/httpbin/docker-compose.yml logs -f bouncer-pep | grep "authz decision"

# Raw engine metrics (counts reflect the total calls you've made so far):
curl -s localhost:9090/metrics | grep authz_evaluations_total
# authz_evaluations_total{access="allow"} 4
# authz_evaluations_total{access="deny"}  5

# Active policies in the engine's in-memory store:
curl -s localhost:9090/metrics | grep '^authz_policy_count '
# authz_policy_count 3
```

To get the full Grafana dashboard experience, point the repo's existing
observability stack at this engine, or just bring it up alongside:

```bash
docker compose -f deploy/observability/docker-compose.yml up -d --build
# Grafana at http://localhost:3000 (admin / admin)
```

## Try your own policy

Add a file under `examples/httpbin/policies/` and restart the PEP (it re-seeds
the engine's in-memory store from the directory on startup):

```bash
cat > examples/httpbin/policies/pol-deny-corp-net.json <<'EOF'
{
  "id": "pol-deny-corp-net",
  "description": "Deny READ from outside the 10.0.0.0/8 corporate network",
  "access": "DENY",
  "target": { "resource_type": "httpbin", "action": "READ" },
  "conditions": [
    { "attribute": "environment.ip_address", "operator": "IN_CIDR", "value": ["10.0.0.0/8"] }
  ]
}
EOF
```

> Note: this denies IPs **inside** `10.0.0.0/8`. Since a CIDR `DENY` flips to
> "deny if inside", a request from the Docker bridge (e.g. `172.x.x.x`) survives
> while one from `10.x.x.x` would be blocked. The default policies don't use
> `environment.ip_address` at all — it's wired so you can experiment.

Then:

```bash
docker compose -f examples/httpbin/docker-compose.yml restart bouncer-pep
```

## Configuration (environment variables)

The PEP reads these (defaults shown), all set for you in `docker-compose.yml`:

| Var                   | Default                   | Meaning                                   |
| :---                  | :---                      | :---                                      |
| `BOUNCER_ENGINE_ADDR` | `bouncer-engine:50051`    | gRPC address of the bouncer-engine PDP    |
| `HTTPBIN_TARGET`      | `http://httpbin`          | Upstream the PEP proxies to on `allow`    |
| `PEP_LISTEN_ADDR`     | `:8080`                   | Where the PEP listens for HTTP traffic    |
| `POLICIES_DIR`        | `/policies`               | Directory of `*.json` policies to seed    |

## Teardown

```bash
docker compose -f examples/httpbin/docker-compose.yml down
```

Add `-v` if you also brought up the observability stack and want to wipe its data
volumes. This demo stack uses no named volumes, so `down` leaves nothing behind.

## Troubleshooting

* **`503 authorization engine unavailable`** — the engine became unreachable
  mid-request. Check `docker compose ... logs bouncer-engine`. The PEP fails
  *closed* in this case (returns 503, never proxies).
* **Everything returns `403` with `reason: "Implict Deny: No matching polices"`**
  — the policies weren't seeded. Check the PEP log for `policies seeded`; the
  `active_policy_count` there should equal the number of `*.json` files in
  `policies/`. If the engine restarted after the PEP started, restart the PEP so
  it re-seeds: `docker compose -f examples/httpbin/docker-compose.yml restart bouncer-pep`.
* **Port already in use** (`8080`/`50051`/`9090`) — another stack (e.g. the
  observability one) is using them. Stop it first, or remap the host ports in
  `docker-compose.yml`.
* **Build fails on `go build ./examples/httpbin/pep`** — ensure generated stubs
  exist at `pkg/gen/authzv1/`. They are committed; if missing, run `make gen`
  (requires [buf](https://buf.build)).

## What this demo is *not*

* **Not production auth** — identity is taken from unauthenticated `X-User` /
  `X-Role` headers purely so the demo is curlable. A real PEP would derive
  principal attributes from a verified JWT, mTLS, or a session. The PEP's
  attribute-extraction point is exactly where that would slot in.
* **Not horizontally scaled** — one engine, one PEP, one httpbin. See the main
  README for performance characteristics and the observability stack.
