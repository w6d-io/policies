package rbac

import future.keywords.every
import future.keywords.in

default allow = false

# ─── EFFECTIVE APP RESOLUTION ───
# Use explicit input.app when provided (simulator, direct OPA calls).
# Otherwise derive from route_map: find which service owns this route.

effective_app = app {
  input.app
  app := input.app
}

effective_app = app {
  not input.app
  some app
  route_config := data.route_map[app]
  some rule in route_config.rules
  rule.method == input.action
  path_matches(rule.path, input.object)
}

# ─── 1. USER ROLE AGGREGATION (per service) ───

# Global roles apply to all services
user_roles_for_app[role] {
  groups := data.bindings.group_membership[input.email]
  group := groups[_]
  group_roles := data.bindings.groups[group]
  global_roles := group_roles["global"]
  role := global_roles[_]
}

# Service-specific roles
user_roles_for_app[role] {
  groups := data.bindings.group_membership[input.email]
  group := groups[_]
  group_roles := data.bindings.groups[group]
  service_roles := group_roles[effective_app]
  role := service_roles[_]
}

# Direct email binding — global
user_roles_for_app[role] {
  email_roles := data.bindings.emails[input.email]
  global_roles := email_roles["global"]
  role := global_roles[_]
}

# Direct email binding — service-specific
user_roles_for_app[role] {
  email_roles := data.bindings.emails[input.email]
  service_roles := email_roles[effective_app]
  role := service_roles[_]
}

# ─── 2. USER PERMISSION AGGREGATION ───

# Permissions from global role definitions
user_permissions[perm] {
  role := user_roles_for_app[_]
  perms := data.roles.global[role]
  perm := perms[_]
}

# Permissions from service-specific role definitions
user_permissions[perm] {
  role := user_roles_for_app[_]
  perms := data.roles[effective_app][role]
  perm := perms[_]
}

# ─── 3. REQUEST ROUTE MATCHING ───

matching_rules[rule] {
  route_config := data.route_map[effective_app]
  rule := route_config.rules[_]
  rule.method == input.action
  path_matches(rule.path, input.object)
}

# ─── 4. PATH MATCHING HELPERS ───

# Exact match
path_matches(pattern, request_path) {
  pattern == request_path
}

# :any* suffix wildcard
path_matches(pattern, request_path) {
  contains(pattern, ":any*")
  prefix_pattern := trim_suffix(pattern, ":any*")
  prefix_parts := split(trim_suffix(prefix_pattern, "/"), "/")
  path_parts := split(request_path, "/")
  count(path_parts) >= count(prefix_parts)
  every i, _ in prefix_parts {
    part_matches(prefix_parts[i], path_parts[i])
  }
}

# :param segment wildcards
path_matches(pattern, request_path) {
  contains(pattern, ":")
  not contains(pattern, ":any*")
  pattern_parts := split(pattern, "/")
  path_parts := split(request_path, "/")
  count(pattern_parts) == count(path_parts)
  all_parts_match(pattern_parts, path_parts)
}

all_parts_match(pattern_parts, path_parts) {
  count(pattern_parts) == count(path_parts)
  every i, _ in pattern_parts {
    part_matches(pattern_parts[i], path_parts[i])
  }
}

part_matches(pattern_part, _) {
  startswith(pattern_part, ":")
}

part_matches(pattern_part, path_part) {
  not startswith(pattern_part, ":")
  pattern_part == path_part
}

# ─── 5. PERMISSION CHECK ───

user_has_permission(permission) {
  user_permissions[permission]
}

# Wildcard grants all
user_has_permission(_) {
  user_permissions["*"]
}

# ─── 5b. TENANT (ORGANIZATION) MEMBERSHIP CHECK ───
#
# Path 3 hybrid multi-org: `input.organization_id` is the org UUID the
# SPA attached to the request (typically via the X-Tenant-Id header
# that opa-authz-proxy promotes into the OPA input). When that field
# is present, the user must be a member of the org to proceed —
# either via the authoritative `metadata_admin.organizations` array
# (mirrored to Redis as `data.bindings.user_organizations[email]`)
# or via the legacy single-org pointer kept as a fallback for
# pre-migration identities.
#
# When `input.organization_id` is absent, this gate passes (no
# behaviour change vs the pre-multi-org rego). Super-admin bypasses
# the gate entirely via the unchanged `allow { user_permissions["*"] }`
# rule below.

# Membership via the multi-org bindings (authoritative).
user_in_org(email, org_id) {
  org_id == data.bindings.user_organizations[email][_]
}

# Membership via the legacy single-org pointer, kept for backward
# compatibility while tenants migrate from a single
# `traits.organization_id` to the `metadata_admin.organizations`
# array. Mirrored into Redis as
# `data.bindings.user_organization_primary[email]`.
user_in_org(email, org_id) {
  org_id == data.bindings.user_organization_primary[email]
}

default tenant_ok = false

tenant_ok {
  not input.organization_id
}

tenant_ok {
  input.organization_id
  user_in_org(input.email, input.organization_id)
}

# ─── 6. USER INFO (simulator / direct OPA queries) ───

user_info = info {
  data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "app": effective_app,
    "groups": data.bindings.group_membership[input.email],
    "roles": user_roles_for_app,
    "permissions": user_permissions,
  }
}

user_info = info {
  not data.bindings.group_membership[input.email]
  not data.bindings.emails[input.email]
  info := {
    "email": input.email,
    "app": effective_app,
    "groups": [],
    "roles": set(),
    "permissions": set(),
  }
}

# ─── 7. ALL-APPS USER INFO ───

user_roles_all_apps[app] = roles {
  some app
  data.roles[app]
  roles := {role |
    groups := data.bindings.group_membership[input.email]
    group := groups[_]
    group_roles := data.bindings.groups[group]
    app_roles := group_roles[app]
    role := app_roles[_]
  }
}

user_info_all = info {
  data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "groups": data.bindings.group_membership[input.email],
    "roles_by_app": user_roles_all_apps,
  }
}

user_info_all = info {
  not data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "groups": [],
    "roles_by_app": {},
  }
}

# ─── 8. ALLOW LOGIC ───

# Super admin / wildcard: bypass route matching AND the tenant gate.
# A wildcard permission means cross-tenant administration is part of
# the role's contract — locking it inside one org would defeat the
# point.
allow {
  user_permissions["*"]
}

# Route has no permission requirement (public endpoint). Still gated
# on the tenant check so an unauthenticated public route on tenant A
# cannot be reached with an X-Tenant-Id pointing at tenant B by a
# user who isn't a member of B.
allow {
  rule := matching_rules[_]
  not rule.permission
  tenant_ok
}

# User holds the required permission AND (when an org context is
# attached) is a member of the requested org.
allow {
  rule := matching_rules[_]
  user_has_permission(rule.permission)
  tenant_ok
}

# ─── SIMULATOR — single-query decision trace ───
# Input: {email, app, action, object}
# Output: {allow, matching_rules[], groups, roles, permissions, super_admin}
#
# Used by jinbe POST /api/admin/rbac/simulate to render a faithful
# decision trace identical to what oathkeeper → opa would produce at
# request time. Avoids JS-side reimplementation drift.

matching_rules_array := [r |
  r := data.route_map[input.app].rules[_]
  r.method == input.action
  path_matches(r.path, input.object)
]

default super_admin = false

# Super-admin = holder of a GLOBAL role with the "*" wildcard.
# A service-scoped admin (e.g. jinbe.admin = ["*"]) does NOT count: that
# is power within one service, not power over system-level resources.
super_admin {
  role := user_roles_for_app[_]
  data.roles.global[role][_] == "*"
}

simulate = result {
  groups := object.get(data.bindings.group_membership, input.email, [])
  result := {
    "allow": allow,
    "matching_rules": matching_rules_array,
    "groups": groups,
    "roles": user_roles_for_app,
    "permissions": user_permissions,
    "super_admin": super_admin,
  }
}

# ─── DECISION — request-time bundle for oathkeeper/opa-authz-proxy ───
# Returns the allow verdict plus the user's server-side group membership
# (sourced from OPAL-fed Redis bindings, never from a client-controlled
# session). opa-authz-proxy reads `groups` and injects X-User-Groups,
# which oathkeeper forwards to the upstream via
# forward_response_headers_to_upstream.

decision = result {
  groups := object.get(data.bindings.group_membership, input.email, [])
  organizations := object.get(data.bindings.user_organizations, input.email, [])
  result := {
    "allow": allow,
    "groups": groups,
    "organizations": organizations,
    "reason": decision_reason,
  }
}

# `not_found` distinguishes "path not declared in any service's route_map"
# from "path declared but the caller lacks the permission" or "user holds
# the permission but is not a member of the requested organization".
# opa-authz-proxy maps:
#   not_found      → 404
#   forbidden      → 403  (no matching permission)
#   forbidden_org  → 403  (matching permission, wrong tenant)
# error-page then renders the right message — leaking a 403 for an
# unknown URL would tell unauthenticated scanners which paths exist.
default decision_reason = "ok"

decision_reason = "not_found" {
  not allow
  count(matching_rules) == 0
}

# Route matched, permission held, but the caller is not a member of
# the requested organization. Only surfaces when input.organization_id
# is present.
decision_reason = "forbidden_org" {
  not allow
  count(matching_rules) > 0
  input.organization_id
  not tenant_ok
  some rule in matching_rules
  user_has_permission(rule.permission)
}

decision_reason = "forbidden" {
  not allow
  count(matching_rules) > 0
  not decision_is_forbidden_org
}

# Helper: true when the deny is specifically the tenant gate.
# Splitting into a dedicated rule keeps `decision_reason = "forbidden"`
# from accidentally matching alongside `forbidden_org`.
default decision_is_forbidden_org = false
decision_is_forbidden_org {
  input.organization_id
  not tenant_ok
  some rule in matching_rules
  user_has_permission(rule.permission)
}
