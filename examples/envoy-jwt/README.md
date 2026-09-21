# bouncer-engine + Envoy + JWT — production-style authn/authz split

A production-shaped demo of [bouncer-engine](../../README.md) as a **Policy
Decision Point (PDP)** behind an **Envoy** edge proxy that verifies JWTs
issued by **Dex** (an OIDC Identity Provider) and enforces the engine's
fine-grained ABAC decisions via Envoy's **external authorization** filter.

The sibling [examples/httpbin](../httpbin) demo is the "hello world": a
hand-written Go reverse proxy that trusts unauthenticated `X-User` / `X-Role`
headers. This example is the next step up the production ladder: identity is
cryptographically verified at the edge, and authorization is a clean
**authn ↔ authz** split across three specialized components.

```
   curl (Bearer JWT)         Envoy :8080 (PEP)                    bouncer-engine :50051 (PDP)
        |                         |                                      ▲
        |--- HTTP :8080 --------->| 1. jwt_authn verifies RS256 JWT       |
        |                         |    against Dex JWKS (http://dex:5556/keys)        CheckAccess
        |                         | 2. forward_payload_header -> x-jwt-payload         |
        |                         | 3. ext_authz (gRPC V3) ----------------> bouncer-extauthz :9191
        |                         |                                  adapter decodes the
        |                         |                                  *already-verified* payload,
        |                         |                                  maps claims -> CheckAccess,
        |                         |                                  calls the engine, returns
        |                         |                                  Ok / Denied / 503 fail-closed
        |                         | 4. allow -> route to httpbin ; deny -> 401/403 JSON
        |<---- 200 / 401 / 403 ---|                                     
        |                         |
        |                         v
        |                      httpbin (internal only)
        |
   (Dex :5556 mints the JWT via the OAuth2 password grant -- scripts/get-token.sh)
```

## Why this demo

Three production concerns the hello-world demo deliberately ignores:

1. **Authentication is real.** Envoy's `jwt_authn` filter verifies the Bearer
   token's RS256 signature against Dex's JWKS and checks the `iss`/`aud`
   claims. A forged or expired token is rejected with `401` before it reaches
   the adapter or httpbin. The adapter never does crypto.
2. **Enforcement is delegated to a battle-tested proxy.** Envoy owns traffic
   management, TLS, retry, and the ext_authz filter; bouncer-engine owns the
   *decision*. This is the standard service-mesh split (PDP vs PEP).
3. **The PEP is thin and protocol-native.** The adapter is a ~250-line Go
   program that implements Envoy's `envoy.service.auth.v3.Authorization` gRPC
   service and translates each `CheckRequest` into a bouncer-engine
   `CheckAccess`. No reverse-proxy logic, no header parsing of the request
   body — Envoy hands it a normalized request.

## Architecture

| Container            | Role | Image / build                              | Listens (in-compose)            | Host port |
| :---                 | :--- | :---                                       | :---                            | :---      |
| `dex`                | IdP  | `dexidp/dex:latest`                        | `:5556` HTTP (token + JWKS)     | `5556`    |
| `envoy`              | PEP  | `envoyproxy/envoy:v1.31-latest`            | `:8080` HTTP                    | `8080`    |
| `bouncer-extauthz`   | adapter | built from `extauthz/Dockerfile`        | `:9191` gRPC (ext_authz)        | *not published* |
| `redis`              | policy bus | `redis:7-alpine`                        | `:6379`                         | `6379`    |
| `bouncer-engine`     | PDP  | built from repo `Dockerfile`               | `:50051` gRPC, `:9090` metrics  | `50051`, `9090` |
| `httpbin`            | upstream | `kong/httpbin:latest`                  | `:80` (internal only)           | *not published* |

All six live on one user-defined bridge network (`bouncer-jwt-net`), so they
address each other by service name. httpbin and the adapter are intentionally
**not** published to the host: the only way in is Envoy on `:8080`.

## File layout

```
examples/envoy-jwt/
├─ README.md
├─ docker-compose.yml          # 6 services on bouncer-jwt-net
├─ envoy/
│  └─ envoy.yaml               # HCM: jwt_authn (Dex provider) + ext_authz gRPC + route→httpbin
├─ dex/
│  └─ config.yaml              # issuer, in-memory storage, 4 static users, public client
├─ extauthz/
│  ├─ main.go                  # envoy.service.auth.v3.Authorization/Check → CheckAccess
│  └─ Dockerfile               # multi-stage, distroless runtime
├─ policies/                   # loaded into the engine by the adapter at startup
│  ├─ pol-deny-blocked-read.json
│  ├─ pol-allow-staff-read.json
│  ├─ pol-allow-admin-write.json
│  └─ pol-allow-finance-write.json
└─ scripts/
   └─ get-token.sh             # password grant to Dex → prints id_token JWT
```

## How it works

### 1. Token issuance (Dex, password grant)
`scripts/get-token.sh alice` POSTs to Dex's `/token` endpoint with
`grant_type=password`. Dex validates the bcrypt hash from `dex/config.yaml`,
issues an RS256-signed `id_token`, and returns it as JSON. The script prints
just the JWT on stdout. The token's claims are:

| claim | value (alice) | source |
| :--- | :--- | :--- |
| `iss` | `http://dex:5556` | Dex issuer |
| `aud` | `bouncer-demo` | client_id |
| `sub` | `local:00000000-...-000000000001` | local connector + userID |
| `email` | `alice@bouncer.dev` | staticPasswords entry |
| `exp` | … | Dex |

> **Note on `groups`:** Dex's local connector does **not** emit a `groups`
> claim (it only populates `sub`/`email`/`name`/`email_verified`). With a real
> upstream connector (LDAP, GitHub, Keycloak) Dex *would* emit `groups`. The
> adapter handles both — see "Claim enrichment" below.

### 2. Edge verification (Envoy `jwt_authn`)
On every request to `:8080`, Envoy's `jwt_authn` filter (`envoy/envoy.yaml`):
- Extracts the `Authorization: Bearer <jwt>` header.
- Fetches Dex's JWKS from `http://dex:5556/keys` (cached 300s).
- Verifies the RS256 signature, `iss == http://dex:5556`, and
  `aud == bouncer-demo`.
- On failure: returns `401` — the request never reaches the adapter.
- On success: attaches the **verified** payload (base64url) to the
  `x-jwt-payload` header (`forward_payload_header`) and continues the filter
  chain.

### 3. Authorization (Envoy `ext_authz` → adapter → bouncer-engine)
The `ext_authz` gRPC filter calls `bouncer-extauthz:9191`
`Authorization/Check` with the normalized request (headers, path, method,
source address). The adapter (`extauthz/main.go`):
1. Reads `x-jwt-payload` and base64url-decodes it. **No signature check** —
   Envoy already did that. If the header is absent, the request is rejected
   as `401` (fail-closed).
2. Extracts `sub`, `email`, `groups` claims.
3. **Claim enrichment** (see below) → derives the `role` set.
4. Builds a `CheckAccessRequest`:

   | source | CheckAccess field |
   | :--- | :--- |
   | `sub` | `principal_id` |
   | enriched roles | `principal.role` (multi-value) |
   | `httpbin` | `resource_type` |
   | request path | `resource_id` **and** `resource_attributes.path` |
   | HTTP method (GET/HEAD/OPTIONS→`READ` else `WRITE`) | `action` |
   | caller IP (from Envoy source address) | `environment.ip_address` |

5. Calls `bouncer-engine.AuthorizationService/CheckAccess` (2s timeout).
6. Maps the response:
   - **allow** → `OkResponse` + adds `x-user`/`x-email`/`x-roles` headers for
     the downstream echo.
   - **deny** → `DeniedResponse` 403 with the engine's `reason`,
     `matched_policy_id`, `evaluation_time_ns` as JSON.
   - **engine unreachable** → `DeniedResponse` 503 (fail-closed, mirrors
     `examples/httpbin/pep`).

Envoy's `failure_mode_allow: false` means if the *adapter* itself is down,
Envoy also fails closed (503) rather than forwarding unauthenticated traffic.

### Claim enrichment (why the adapter maps email → roles)
This is the one demo-specific sleight of hand, and it's worth understanding
because the *pattern* is real even though the *data* is a demo artifact.

Dex's local connector can't emit `groups` (a known limitation — there's no
group field on `staticPasswords`). The adapter therefore does claim
enrichment at the PEP:

```go
func enrichRoles(c jwtClaims) []string {
    if len(c.Groups) > 0 {           // production path: real IdP emits groups
        return c.Groups
    }
    if roles, ok := demoClaimMap[c.Email]; ok {  // demo path: map verified email
        return roles
    }
    return []string{}
}
```

**Production path** (`groups` present): the adapter uses the JWT's groups
verbatim — zero mapping, zero special-casing. This is exactly what you'd get
pointing Dex at LDAP/Keycloak, or pointing Envoy directly at Auth0/Okta.

**Demo path** (`groups` empty): the adapter maps the *verified* `email` to a
hardcoded role vocabulary (`demoClaimMap`). Claim enrichment at the PEP is a
standard real-world pattern — translating an IdP's claim vocabulary into your
application's authorization vocabulary — so the *shape* is production-honest;
only the *lookup table* is a demo artifact. In a real deployment that lookup
would live in your IdP's claim-script, a directory service, or a real
`groups` claim, not in adapter code.

## Prerequisites

* Docker + Docker Compose v2 (`docker compose version` prints a v2 number).
* `jq` (for `get-token.sh`; install via your package manager).
* No Go toolchain is required to *run* the demo — both Go services build
  inside multi-stage Docker images.

## Run it

From the repo root:

```bash
docker compose -f examples/envoy-jwt/docker-compose.yml up -d --build
```

First run takes a few minutes (builds the engine + adapter Go images). Check
readiness — the adapter should have seeded 4 policies:

```bash
docker compose -f examples/envoy-jwt/docker-compose.yml logs bouncer-extauthz | grep "policies seeded"
# -> {"msg":"policies seeded into bouncer engine","count":4,"stream":"authpolicy:events",...}

# Cross-check the live policy gauge (should be 4 once the engine consumes the stream):
curl -s localhost:9090/metrics | grep '^authz_policy_count '
# -> authz_policy_count 4
```

## Walkthrough

Mint a token for each user (password = first name), then curl Envoy with it
as a Bearer header. `-s -o /dev/null -w "%{http_code}\n"` prints just the
status code; drop it to see httpbin's echo body on allowed calls.

```bash
# Mint tokens for all four demo users.
ALICE=$(examples/envoy-jwt/scripts/get-token.sh alice)
BOB=$(examples/envoy-jwt/scripts/get-token.sh bob)
CAROL=$(examples/envoy-jwt/scripts/get-token.sh carol)
MALLORY=$(examples/envoy-jwt/scripts/get-token.sh mallory)
```

### 1. Staff READ is allowed.
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $ALICE" localhost:8080/get   # -> 200  (admin)
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $BOB"   localhost:8080/get   # -> 200  (user)
```

### 2. No JWT → 401 (Envoy rejects before the adapter is called).
```bash
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/get                                    # -> 401
```

### 3. Explicit DENY: a blocked principal is denied even on READ.
```bash
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $MALLORY" localhost:8080/get # -> 403
```
```bash
curl -s -H "Authorization: Bearer $MALLORY" localhost:8080/get
# {
#   "allowed": false,
#   "reason": "Explicit Deny: Matched deny policy",
#   "matched_policy_id": "pol-deny-blocked-read",
#   "evaluation_time_ns": 5941
# }
```

### 4. WRITE to standard endpoints requires role set exactly `["admin"]` (EQUALS + path REGEX).
`pol-allow-admin-write` combines a path REGEX (`^/(post|put|patch|delete)$`)
with an EQUALS set-equality check on `principal.role`. The path condition
scopes this policy to httpbin's standard write endpoints so it doesn't shadow
the finance policy (next).
```bash
# alice (roles=[admin]) -> allowed by pol-allow-admin-write.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $ALICE" -X POST localhost:8080/post          # -> 200
# bob (roles=[user]) -> no matching allow policy -> implicit deny.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $BOB"   -X POST localhost:8080/post          # -> 403
# carol (roles=[admin,finance]) -> EQUALS ["admin"] does NOT match (set equality) -> implicit deny.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $CAROL" -X POST localhost:8080/post          # -> 403
```
This is the key teaching point: `EQUALS` compares the **full multi-value
set**, so carol (admin+finance) is *not* granted general write access by
`pol-allow-admin-write`. She is scoped to `/anything/finance/*` only (next).

### 5. Multi-condition ABAC: carol can WRITE `/anything/finance/*` (REGEX + CONTAINS_ALL).
`pol-allow-finance-write` combines a resource attribute (`resource.path`
REGEX `^/anything/finance/`) with a principal attribute (`principal.role`
CONTAINS_ALL `["admin","finance"]`). We use httpbin's `/anything/*` catch-all
endpoint, which responds 200 to any path and echoes the request — it stands in
for a real finance service's routes.
```bash
# carol (admin+finance) writing /anything/finance/budget -> allowed.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $CAROL" -X POST localhost:8080/anything/finance/budget   # -> 200
# alice (admin only) writing /anything/finance/budget -> missing 'finance' -> 403.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $ALICE" -X POST localhost:8080/anything/finance/budget   # -> 403
# carol writing /post (non-finance) -> no matching allow policy -> 403.
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $CAROL" -X POST localhost:8080/post                       # -> 403
```

### 6. Allowed calls reach httpbin, which echoes the identity headers the adapter injected.
```bash
curl -s -H "Authorization: Bearer $ALICE" localhost:8080/get \
  | jq '.headers | with_entries(select(.key|ascii_downcase|test("x-(user|email|roles)")))'
# {
#   "X-Email": "alice@bouncer.dev",
#   "X-Roles": "admin",
#   "X-User": "CiQwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDESBWxvY2Fs"
# }
```
These are the *trusted* headers the adapter set after the engine allowed the
call — not the client's original `Authorization` header. A client cannot
forge them: Envoy's `jwt_authn` runs first, and any client-supplied
`x-user`/`x-roles` would be overwritten by the adapter's `OkResponse` headers.
(The `x-jwt-payload` header, also visible in httpbin's echo, is set by Envoy's
`jwt_authn` filter — not the adapter.)

## Observe the engine

The adapter logs every decision; the engine exposes Prometheus metrics:

```bash
# Adapter decision log (one line per request):
docker compose -f examples/envoy-jwt/docker-compose.yml logs -f bouncer-extauthz | grep "authz decision"

# Raw engine metrics (counts reflect the total calls you've made so far):
curl -s localhost:9090/metrics | grep authz_evaluations_total
# authz_evaluations_total{access="allow"} 6
# authz_evaluations_total{access="deny"}  7

# Active policies in the engine's in-memory store:
curl -s localhost:9090/metrics | grep '^authz_policy_count '
# authz_policy_count 4
```

For the full Grafana dashboard experience, bring up the repo's observability
stack alongside (it scrapes the same engine):

```bash
docker compose -f deploy/observability/docker-compose.yml up -d --build
# Grafana at http://localhost:3000 (admin / admin)
```

## Configuration (environment variables)

The adapter reads these (defaults shown), all set for you in `docker-compose.yml`:

| Var                   | Default                   | Meaning                                   |
| :---                  | :---                      | :---                                      |
| `BOUNCER_ENGINE_ADDR` | `bouncer-engine:50051`    | gRPC address of the bouncer-engine PDP    |
| `EXTAUTHZ_LISTEN_ADDR`| `:9191`                   | Where the ext_authz gRPC server listens   |
| `POLICIES_DIR`        | `/policies`               | Directory of `*.json` policies to seed    |
| `REDIS_ADDR`          | `localhost:6379`          | Redis address the adapter publishes policy updates to |
| `JWT_PAYLOAD_HEADER`  | `x-jwt-payload`           | Header Envoy attaches the verified payload to |

## Teardown

```bash
docker compose -f examples/envoy-jwt/docker-compose.yml down
```

Add `-v` if you also brought up the observability stack and want to wipe its
data volumes. This demo stack uses no named volumes, so `down` leaves nothing
behind.

## Troubleshooting

* **`401` on every request** — Envoy's `jwt_authn` rejected the token. Check
  that you're sending `Authorization: Bearer <jwt>` (note the scheme), that
  the token isn't expired, and that Dex is reachable: `curl -s
  http://localhost:5556/keys | jq '.keys | length'`. Envoy logs the jwt_authn
  rejection reason: `docker compose ... logs envoy | grep jwt`.
* **`403` with `reason: "Implict Deny: No matching polices"` on every
  request** — the policies weren't applied. Check the adapter log for
  `policies seeded` (`count` should equal the number of `*.json` files in
  `policies/`) and the engine gauge `authz_policy_count`. The engine replays
  the Redis stream on startup, so an engine restart does not require
  re-seeding. If Redis was wiped, restart the adapter:
  `docker compose -f examples/envoy-jwt/docker-compose.yml restart bouncer-extauthz`.
* **`503` on every request** — the adapter can't reach the engine, or Envoy
  can't reach the adapter. Check `docker compose ... logs bouncer-extauthz`
  for `CheckAccess failed` and `docker compose ... logs envoy` for ext_authz
  stream errors. `failure_mode_allow: false` means Envoy fails closed here.
* **`get-token.sh: no id_token in response`** — Dex rejected the password
  grant. Double-check the username (full email, e.g. `alice@bouncer.dev`)
  and password (first name). The raw Dex response is printed on stderr.
* **Build fails on `go build ./examples/envoy-jwt/extauthz`** — ensure
  generated stubs exist at `pkg/gen/authzv1/`. They are committed; if
  missing, run `make gen` (requires [buf](https://buf.build)). The
  `go-control-plane` dependency is pulled by `go mod tidy`.
* **Port already in use** (`8080`/`5556`/`50051`/`9090`/`6379`) — another stack (e.g.
  the httpbin or observability one) is using them. Stop it first, or remap
  the host ports in `docker-compose.yml`.

## What this demo is *not*

* **Not production authz wiring** — the claim-enrichment map
  (`demoClaimMap`) is a demo artifact. In production, use a real `groups`
  claim from your IdP (the adapter already prefers it) or an external
  directory; never hardcode identity→role mappings in PEP code.
* **Not production IdP config** — Dex runs with in-memory storage and the
  local password connector over plain HTTP. A real deployment uses persistent
  storage, TLS, and an upstream connector (LDAP/OIDC) for both groups and
  identity.
* **Not a token-format recommendation** — the demo sends the OIDC `id_token`
  as the Bearer credential so a single JWT carries the claims the adapter
  needs. Production systems typically use an OAuth2 `access_token` (often an
  introspected opaque token) for API authorization, with audience and scope
  validation; the authn/authz *split* shown here is unchanged.
* **Not horizontally scaled** — one of each container. See the main README
  for the engine's performance characteristics and the observability stack.
