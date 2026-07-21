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

# ─── 5b. ORG → SERVICE ENTITLEMENT GATE (J14 v2 — server-derived) ───
#
# Replaces the old header-based Path-3 tenant gate (X-Tenant-Id →
# input.organization_id → tenant_ok). That gate trusted a browser-supplied
# header to name the org and was fail-OPEN when the header was absent; this
# one is computed ENTIRELY from server-side state:
#
#   input.email                          — the Kratos session subject
#   effective_app                        — the service the route resolves to
#   data.bindings.user_organizations     — OPAL-fed org membership (authoritative)
#   data.org_service_map                 — the SAME org→service map that
#                                          rbac.delegation.services_of consumes
#
# MODEL (J14 v3 — ARRAY BUNDLES). Each org "bundles" a SET of services via
# data.org_service_map[org] (drawn from the route_map service namespace — each
# value equals some effective_app; live data uses route_map keys like "fleet").
# The map is now ARRAY-valued (org → ["svc", ...]); services_of() below is
# scalar-tolerant so legacy string values still work during the migration break
# window. A request to service S by user U is entitled iff at least one org U
# belongs to bundles S. The union is expressed by iterating the user's orgs and,
# within each, iterating its service bundle.
#
# NO-ORG FALLBACK (activation safety, critical). A caller who belongs to zero
# orgs is NOT gated — org_service_ok passes and legacy RBAC alone decides. This
# is what makes turning the gate on safe for un-orged identities: they are not
# locked out, they simply keep the pre-gate behaviour. object.get supplies the
# empty default so an email ABSENT from the (present) user_organizations map is
# treated as "no orgs" → ungated.
#
# FAIL-CLOSED on missing data. If the user_organizations map itself is absent
# (OPAL not feeding it), object.get's undefined first argument makes the
# fallback clause undefined and user_entitled_services empty, so org_service_ok
# stays false and permission-gated data-plane requests DENY — a lookup failure
# never yields an allow. An org present in user_organizations but ABSENT from
# org_service_map yields no services (services_of undefined) → that org
# contributes nothing → still fail-closed, never an implicit allow-all.

# Scalar-tolerant org→services resolver. Kept as a LOCAL copy of
# rbac.delegation.services_of (identical logic) so the request-time gate reads
# the SAME map the SAME way as the grant-time delegation policy, WITHOUT coupling
# the hot request path to the delegation package. Array value → set of members;
# legacy string → singleton set; undefined when the org is unmapped (fail-closed).
services_of(org) = svcs {
  val := data.org_service_map[org]
  is_array(val)
  svcs := {s | some s in val}
}

services_of(org) = svcs {
  val := data.org_service_map[org]
  is_string(val)
  svcs := {val}
}

# Services entitled to the caller, unioned over every org they belong to and, per
# org, over that org's whole service bundle.
user_entitled_services[svc] {
  some org in object.get(data.bindings.user_organizations, input.email, [])
  some svc in services_of(org)
}

default org_service_ok = false

# NO-ORG fallback — caller belongs to no org → ungated (legacy behaviour).
org_service_ok {
  count(object.get(data.bindings.user_organizations, input.email, [])) == 0
}

# Org'd caller — the resolved service must be bundled by ≥1 of the caller's orgs.
org_service_ok {
  user_entitled_services[effective_app]
}

# ─── 5c. ORG-ADMIN ROSTER (per-org admin list) ───
# "Org admin" is a PER-ORG designation, NOT a global flag: `data.org_admin_map`
# is a map orgId → [admin email, ...] (published by jinbe, symmetric with
# `org_service_map` — an org has a service bundle AND an admin roster). A user
# administers an org iff they are on ITS roster AND belong to it (see
# rbac.delegation.manageable_orgs). Per-org: a user can be an admin of org A and a
# plain member of org B — the two rosters are independent.
#
# Being an org admin confers NO standing service permission; its only effect is
# the org-management capability the policy grants below. The roster is edited only
# via the super_admin-gated org endpoint, so an org admin can never add themselves
# or promote a peer, and granting a user ordinary service permissions never makes
# them an org admin.
is_org_admin_of(email, org) {
  data.org_admin_map[org][_] == email
}

# The fixed capability an org admin gets on org-management routes — membership
# management ONLY, never arbitrary service permissions.
org_management_permission := {
  "org:manage_users",
  "users:read",
  "users:create",
  "users:assign_group",
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

# Super admin / wildcard: bypass route matching AND the org→service gate.
# A wildcard permission means cross-org administration is part of the role's
# contract — scoping it to a single org's service bundle would defeat the
# point. (NO org_service_ok clause here — fully exempt, unchanged from base.)
allow {
  user_permissions["*"]
}

# Route has no permission requirement (public endpoint). NOT org-gated: a
# public route is public regardless of the caller's org bundle. (The old
# header gate tried to fence public routes per-tenant off a spoofable header;
# with the header gone there is nothing trustworthy to fence on, so this
# reverts to plain "public means public".)
allow {
  rule := matching_rules[_]
  not rule.permission
}

# Data-plane authorization: the caller holds the route's required permission
# (RBAC — WHAT they may do) AND the resolved service is entitled to one of the
# caller's orgs (org→service gate — WHICH services they may reach). The gate is
# layered ON TOP of RBAC; it never loosens the permission check.
allow {
  rule := matching_rules[_]
  user_has_permission(rule.permission)
  org_service_ok
}

# ─── ORG-SCOPED DELEGATION (defense-in-depth for the centralised mgmt API) ───
# The org-user management routes physically live in the jinbe route_map, so the
# clauses above resolve their permission under app=jinbe. A per-service org admin
# (e.g. a kuma org_admin holding org:manage_users in kuma, not jinbe) would be
# denied there. This clause additionally allows such a request when the caller
# holds the route's required permission resolved in ANY service the
# ORGANISATION's bundle maps to — taken from the :orgId segment of the path.
# jinbe then independently re-enforces the SPECIFIC org
# (delegation.manageable_orgs) + containment, so the gateway and the app are two
# independent authorization layers.
#
# ADDITIVE & FAIL-CLOSED: fires only for a declared route that HAS a required
# permission, whose path carries an org id that maps to a bundle in which the
# caller actually holds that permission (or "*") in SOME bundled service. It can
# only turn a specific org-admin DENY into an ALLOW — it never changes any
# non-org-scoped decision and never grants more than the route's own permission.
# An unmapped org → services_of undefined → no bundled service → no allow.
#
# J14 v3 NOTE — this clause is intentionally NOT gated on org_service_ok. Its
# effective_app is the service that physically HOSTS the org-management route
# (jinbe), which is generally NOT a service the caller's own org bundles (e.g. a
# fleet-org admin manages users through the jinbe-hosted
# /api/organizations/:orgId/users route). AND-ing org_service_ok here would deny
# every legitimate cross-service delegated org admin. This clause already carries
# its OWN server-derived org scoping: the org id is read from the request PATH,
# resolved through the SAME data.org_service_map (now array-valued via
# services_of), and the caller must hold the route permission in SOME service of
# that org's bundle — a stricter, path-anchored tenant boundary than the
# user-org→effective_app check. Nothing browser-controlled remains here.
allow {
  rule := matching_rules[_]
  rule.permission
  org := org_id_from_object(input.object)
  some svc in services_of(org)
  org_perms := data.rbac.user_permissions with input as {"email": input.email, "app": svc}
  perm_satisfied(org_perms, rule.permission)
}

# ─── ORG-ADMIN capability (per-org roster) ───
# A user on org's admin roster (data.org_admin_map) may reach THAT org's
# management routes, limited to the fixed org-management permission set. The org
# id is read from the request PATH (org_id_from_object); the caller must be BOTH
# on that org's roster AND a member of it (server-side; nothing browser-controlled
# is trusted). jinbe then independently re-enforces delegation.manageable_orgs +
# can_grant, so gateway and app are two layers. Fail-closed: a non-org path, an
# org the caller does not administer or belong to, or a route permission outside
# the management set → no allow.
allow {
  rule := matching_rules[_]
  org_management_permission[rule.permission]
  org := org_id_from_object(input.object)
  is_org_admin_of(input.email, org)
  orgs := object.get(data.bindings.user_organizations, input.email, [])
  org == orgs[_]
}

# Organisation id from /api/organizations/<org>/... (any method). Undefined for
# any other path shape, so the clause above simply does not fire.
org_id_from_object(obj) = org {
  parts := split(trim_prefix(obj, "/"), "/")
  parts[0] == "api"
  parts[1] == "organizations"
  org := parts[2]
  org != ""
}

perm_satisfied(perms, perm) {
  perms[perm]
}

perm_satisfied(perms, _) {
  perms["*"]
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
# forward_response_headers_to_upstream. `organizations` is forwarded the
# same way (X-User-Organizations) so the SPA can render the org switcher.

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
# from "path declared but the caller lacks the permission" or "caller holds
# the permission but the resolved service is not bundled by any of their orgs".
# opa-authz-proxy maps:
#   not_found      → 404
#   forbidden      → 403  (no matching permission)
#   forbidden_org  → 403  (permission held, service not entitled for the org)
# error-page then renders the right message — leaking a 403 for an
# unknown URL would tell unauthenticated scanners which paths exist.
default decision_reason = "ok"

decision_reason = "not_found" {
  not allow
  count(matching_rules) == 0
}

# Route matched and the caller holds the required permission, but the resolved
# service is not in the bundle of any org the caller belongs to → org→service
# entitlement deny. This is the J14 v2 replacement for the old header-based
# "forbidden_org"; the reason string is kept so opa-authz-proxy's
# forbidden_org→403 mapping and the error-page copy do not need to change.
# Only reachable for an org'd caller (an un-orged caller passes org_service_ok
# via the no-org fallback, so this never fires for them).
decision_reason = "forbidden_org" {
  not allow
  count(matching_rules) > 0
  some rule in matching_rules
  rule.permission
  user_has_permission(rule.permission)
  not org_service_ok
}

decision_reason = "forbidden" {
  not allow
  count(matching_rules) > 0
  not decision_is_forbidden_org
}

# Helper: true when the deny is specifically the org→service gate.
# Splitting into a dedicated rule keeps `decision_reason = "forbidden"`
# from accidentally matching alongside `forbidden_org`.
default decision_is_forbidden_org = false
decision_is_forbidden_org {
  some rule in matching_rules
  rule.permission
  user_has_permission(rule.permission)
  not org_service_ok
}
