# Adding Engine Test Cases

The engine is tested through JSON scenario files under `internal/engine/testdata/`.
Every `*.json` file in that directory is discovered and executed automatically by
`TestEngine_FromJSON`, which runs each scenario as its own subtest against a fresh
engine instance.

Existing files:

* `testdata/basic_operators.json` — allow scenarios for each condition operator.
* `testdata/deny_scenarios.json` — implicit deny, target-mismatch, and explicit
  `DENY` scenarios.
* `testdata/regex_scenarios.json` — REGEX operator: match, no match, case
  sensitivity, complex patterns, and DENY with regex.

## Test case schema

Each file is a JSON array of case objects:

| Field              | Type   | Required | Description                                            |
| ------------------ | ------ | -------- | ------------------------------------------------------ |
| `name`             | string | yes      | Subtest name (shown in `go test -v` output).           |
| `policies`         | array  | yes      | Policies to load into the engine for this case.        |
| `request`          | object | yes      | The authorization request to evaluate.                 |
| `want_allowed`     | bool   | yes      | Expected `Allowed` result.                             |
| `want_policy_id`   | string | yes      | Expected `MatchedPolicyID` (`""` if denied).           |
| `want_reason`      | string | no       | If set, the exact `Reason` text must match.            |
| `want_err`         | bool   | no       | If `true`, the call must return an error.              |

### Policy object

| Field         | Type    | Description                                     |
| ------------- | ------- | ----------------------------------------------- |
| `id`          | string  | Policy identifier.                              |
| `description` | string  | Human-readable description (used in `Reason`).  |
| `access`      | string  | `"ALLOW"` or `"DENY"`.                          |
| `target`      | object  | `resource_type` + `action` the policy applies to. |
| `conditions`  | array   | Conditions that must all evaluate true.         |

Each condition has:

| Field       | Type     | Description                                  |
| ----------- | -------- | -------------------------------------------- |
| `attribute` | string   | Dot-prefixed key, e.g. `environment.network_zone`. |
| `operator`  | string   | `EQUALS`, `CONTAINS_ALL`, `CONTAINS_ANY`, `IN_CIDR`, `BETWEEN`, or `REGEX`. |
| `value`     | []string | Values the condition compares against.       |

### Request object

| Field                  | Type          | Description                          |
| ---------------------- | ------------- | ------------------------------------ |
| `resource_type`        | string        | Type of resource being accessed.     |
| `action`               | string        | Action being performed.              |
| `principal_attributes` | object        | Map of attribute name to value list. |
| `resource_attributes`  | object        | Map of attribute name to value list. |
| `environment_attributes` | object      | Map of attribute name to value list. |

## Adding a case

1. Pick the file that fits the scenario (or create a new `testdata/*.json` file).
2. Append a new object to the array.
3. Define the policies the case needs, the request, and the expected outcome.
4. Run the tests:

   ```sh
   go test ./internal/engine/ -v -run TestEngine_Test
   ```

## Example

The following case allows DevOps engineers to read `audit-log` resources as long
as the request originates from the internal VPN:

```json
{
  "name": "DevOps may read audit logs from internal VPN",
  "policies": [
    {
      "id": "pol-audit-001",
      "description": "DevOps can read audit logs from the internal VPN",
      "access": "ALLOW",
      "target": {
        "resource_type": "audit-log",
        "action": "READ"
      },
      "conditions": [
        {
          "attribute": "principal.roles",
          "operator": "CONTAINS_ALL",
          "value": ["DevOps"]
        },
        {
          "attribute": "environment.network_zone",
          "operator": "EQUALS",
          "value": ["internal-vpn"]
        }
      ]
    }
  ],
  "request": {
    "resource_type": "audit-log",
    "action": "READ",
    "principal_attributes": {
      "roles": ["DevOps"]
    },
    "environment_attributes": {
      "network_zone": ["internal-vpn"]
    }
  },
  "want_allowed": true,
  "want_policy_id": "pol-audit-001"
}
```

## Notes and gotchas

* **Each case gets its own engine.** Policies never leak between cases, and a
  case's `policies` array must contain everything the scenario needs.
* **`EQUALS` is set equality, not prefix matching.** The request values must match
  the condition values exactly, in any order. `["internal-data"]` will *not* match
  a condition value of `["internal-data", "backup-mgmt"]`.
* **Implicit deny.** If no policy matches (target mismatch or condition failure),
  the engine returns `"allowed": false` with an empty `want_policy_id` and reason
  `"Implict Deny: No matching polices"`.
* **`want_reason` pins exact text.** Only set it when you want to lock the reason
  string (e.g. the implicit-deny message); omit it otherwise.
* **Prefer unique scenarios.** If a case would produce the same outcome as an
  existing one (same target, conditions, and attributes), consider extending the
  existing case instead of adding a duplicate.
