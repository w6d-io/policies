# w6d-io / policies

OPA (Rego) policies for the W6D authorization stack. The single source of
truth for `package rbac` — loaded by [OPAL][opal] and evaluated by [Open
Policy Agent][opa] in front of every protected service.

This repository ships exactly one file: [`rbac.rego`](./rbac.rego). It is
data-driven — the policy itself is static, while groups, roles, bindings
and route maps are pushed in at runtime by OPAL from an external store
(in W6D: Redis, written by [Jinbe][jinbe]).

[opal]: https://github.com/permitio/opal
[opa]:  https://www.openpolicyagent.org/
[jinbe]: https://github.com/w6d-io

---

## Pipeline

```
                  ┌──────────────┐  WebSocket push (<100ms)
   admin change ─►│ OPAL Server  │──────────────┐
                  └──────────────┘              │
                                                ▼
   browser ──► oathkeeper ──► opa-authz-proxy ──► OPA ◄── rbac.rego
                                  │                ▲
                                  │                │  data.bindings.*
                                  │                │  data.roles.*
                                  │                │  data.route_map.*
                                  ▼
                          upstream service
                          + X-User-Id
                          + X-User-Email
                          + X-User-Groups   ← from /v1/data/rbac/decision
```

[Oathkeeper][oathkeeper]'s `remote_json` authorizer calls OPA via the
[opa-authz-proxy][proxy] at `/v1/data/rbac/decision`. The proxy reads
`{allow, groups}`, returns HTTP 200/403 based on `allow`, and emits the
groups as the `X-User-Groups` response header. Oathkeeper forwards that
header to the upstream via `forward_response_headers_to_upstream`.

[oathkeeper]: https://www.ory.sh/docs/oathkeeper
[proxy]:      https://github.com/w6d-io/opa-authz-proxy

---

## Entry points

| Rule                | Returns                                   | Caller                      |
| ------------------- | ----------------------------------------- | --------------------------- |
| `data.rbac.allow`   | `bool`                                    | legacy / smoke tests        |
| `data.rbac.decision`| `{ "allow": bool, "groups": [string] }`   | `opa-authz-proxy` at request time |
| `data.rbac.simulate`| full trace (rules, roles, perms, etc.)    | admin simulator UI          |
| `data.rbac.user_info` / `user_info_all` | per-app / cross-app user view | admin UI |

`decision` is the canonical request-time endpoint. It returns groups
sourced from `data.bindings.group_membership[input.email]` — i.e. the
trusted server-side bindings pushed by OPAL — never from a client
session. This keeps Kratos `metadata_admin` private (never exposed via
`/sessions/whoami`) while still giving upstreams the user's groups.

---

## Input

```json
{
  "input": {
    "sub":    "<kratos identity id>",
    "email":  "user@example.com",
    "object": "/api/clusters/abc",
    "action": "GET",
    "app":    "jinbe"
  }
}
```

| Field    | Required | Description                                           |
| -------- | -------- | ----------------------------------------------------- |
| `sub`    | no       | Opaque subject id, used by upstreams                  |
| `email`  | yes      | Lookup key into `data.bindings.group_membership`      |
| `object` | yes      | Request path                                          |
| `action` | yes      | HTTP method                                           |
| `app`    | no       | Service name. When omitted, derived from `route_map`  |

When `input.app` is omitted, `effective_app` walks `data.route_map[*]`
and picks the first service whose rules match (method + path). This is
how multi-service deployments avoid hard-coding `app` per Oathkeeper
rule.

---

## Data shape

Pushed in by OPAL (key paths under `data.*`):

```
data.bindings.group_membership  { "<email>": ["<group>", ...] }
data.bindings.groups            { "<group>": { "<app>|global": ["<role>", ...] } }
data.bindings.emails            { "<email>": { "<app>|global": ["<role>", ...] } }
data.roles.<app>                { "<role>": ["<permission>", ...] }
data.roles.global               { "<role>": ["<permission>", ...] }
data.route_map.<app>.rules      [ { "method": "GET", "path": "/x/:id", "permission": "x:read" } ]
```

`global` roles apply to every app. A permission of `"*"` is a wildcard
and short-circuits route matching (super-admin).

### Path patterns

`path_matches(pattern, path)` understands three forms:

| Pattern             | Matches                                            |
| ------------------- | -------------------------------------------------- |
| `/api/health`       | exact only                                         |
| `/api/users/:id`    | one segment wildcard per `:param`                  |
| `/api/files/:any*`  | prefix wildcard — matches any tail (incl. slashes) |

`:any*` must appear as the last segment.

---

## Allow logic

```rego
default allow = false

# 1. Super-admin (any wildcard permission) bypasses route matching
allow { user_permissions["*"] }

# 2. Public endpoints (rule has no `permission` field)
allow { rule := matching_rules[_]; not rule.permission }

# 3. User holds the rule's required permission
allow { rule := matching_rules[_]; user_has_permission(rule.permission) }
```

`user_permissions` is the union of permissions for every role the user
holds, taken from both global and per-app role definitions.

---

## Testing locally

```bash
# 1. Start OPA with the policy
opa run --server rbac.rego

# 2. Push some test data
curl -X PUT http://localhost:8181/v1/data/bindings -d '{
  "group_membership": { "alice@example.com": ["editors"] },
  "groups": { "editors": { "jinbe": ["writer"] } }
}'
curl -X PUT http://localhost:8181/v1/data/roles -d '{
  "jinbe": { "writer": ["docs:write"] }
}'
curl -X PUT http://localhost:8181/v1/data/route_map -d '{
  "jinbe": { "rules": [
    { "method": "POST", "path": "/api/docs", "permission": "docs:write" }
  ]}
}'

# 3. Ask for a decision
curl -X POST http://localhost:8181/v1/data/rbac/decision -d '{
  "input": {
    "email":  "alice@example.com",
    "object": "/api/docs",
    "action": "POST",
    "app":    "jinbe"
  }
}'
# => { "result": { "allow": true, "groups": ["editors"] } }
```

---

## Versioning

The policy is small and stable; changes are tracked through git history.
The OPAL server polls this repository on a schedule (default 30s) and
pushes changes to every connected OPA replica in <100ms.

Breaking changes to input/output shape (e.g. renaming a top-level
`data.*` key) require a coordinated rollout with the producers of that
data (Jinbe) and the consumers of decisions (Oathkeeper, the proxy).

---

## License

Apache-2.0
