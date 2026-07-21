package rbac.delegation

import future.keywords.every
import future.keywords.in

# ── Delegation grant decision ──────────────────────────────────────────────
# "May org-admin ACTOR grant TARGET_GROUP to a user in TARGET_ORG?"
# input: { "actor": { "email": <email> }, "target_group": <group>, "target_org": <orgId> }
#
# Delegation is safe iff CONTAINMENT holds: the actor may grant only permissions
# they already hold, only in an org they administer, and never a global group.
# Actor permissions are resolved from data via rbac.user_permissions (the SAME
# resolver the request authorizer uses) so the two cannot disagree — never taken
# from caller input. Every rule fails closed on missing/undefined data.
#
# J14 v3 — ARRAY-VALUED org_service_map. Each org bundles a SET of services
# (data.org_service_map[org] = ["svc", ...]). services_of() is scalar-tolerant:
# a legacy string value is treated as a singleton bundle so the policy is
# correct during the migration break window (no drift between old scalar and new
# array data). Reach + grants span that org's whole service BUNDLE; containment
# is enforced PER-SERVICE (a perm the group confers in service S must be held by
# the actor resolved in S, never satisfied by a perm the actor holds in a
# different bundled service).

# Actor's resolved permission set in (global ∪ <svc>), via the shared resolver.
actor_perms_in(svc) = perms {
	perms := data.rbac.user_permissions with input as {"email": input.actor.email, "app": svc}
}

actor_holds(perms, p) {
	perms[p]
}

actor_holds(perms, _) {
	perms["*"]
}

# Service BUNDLE that backs a given org, as a SET. Scalar-tolerant:
#   array value  → the set of its members (real bundles).
#   string value → singleton set (legacy scalar data, migration break window).
# Undefined when the org has no mapping (fail-closed — an unmapped org yields no
# services, never an implicit allow-all).
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

# Every permission a group confers, across ALL its scopes (global + each service).
# data.roles["global"] is data.roles.global, so data.roles[svc][role] is uniform.
perms_of_group(g) = ps {
	ps := {p |
		some svc
		roles := data.bindings.groups[g][svc]
		some role in roles
		p := data.roles[svc][role][_]
	}
}

# Permissions a group confers SPECIFICALLY in service `svc` (only the roles bound
# under that scope key, resolved against data.roles[svc]). This is what makes
# containment per-service: the group's fleet-scope perms are checked against the
# actor's fleet perms, its kuma-scope perms against the actor's kuma perms, etc.
perms_of_group_in(g, svc) = ps {
	ps := {p |
		some role in data.bindings.groups[g][svc]
		p := data.roles[svc][role][_]
	}
}

# Group confers global power (non-empty "global" role list).
group_has_global(g) {
	count(data.bindings.groups[g]["global"]) > 0
}

# Orgs the actor administers: they are on the org's admin ROSTER
# (data.org_admin_map[org], a per-org list of admin emails) AND belong to it.
# PER-ORG — a user administers only the orgs they are listed for, so they can be
# an admin of org A and a plain member of org B (the rosters are independent).
# Membership (user_organizations) is the HARD own-org boundary — an org admin can
# never administer an org they do not belong to, even if erroneously rostered.
manageable_orgs[org] {
	some org in data.bindings.user_organizations[input.actor.email]
	data.org_admin_map[org][_] == input.actor.email
}

# Services the actor administers — the UNION of the bundles of every org they
# administer.
managed_services[svc] {
	some org in manageable_orgs
	some svc in services_of(org)
}

# ── Bundle-containment predicate (replaces the old single-service gate) ──────
# The target group is a legal org-endpoint target iff:
#   • it is NON-GLOBAL (global groups go through the global admin endpoint), and
#   • it confers ≥1 permission (no vacuous grant), and
#   • every service it spans is inside the TARGET org's service BUNDLE
#     (group's service set ⊆ services_of(input.target_org)).
# Fail-closed: an unmapped target org makes services_of undefined → the subset
# check is impossible → predicate false → BOTH can_grant tiers deny. A group
# spanning any service outside the org's bundle is rejected (the tenant boundary
# is the bundle, not a single service).
default group_in_org_bundle = false

group_in_org_bundle {
	not group_has_global(input.target_group)
	count(perms_of_group(input.target_group)) > 0
	bundle := services_of(input.target_org)
	every svc, _ in data.bindings.groups[input.target_group] {
		bundle[svc]
	}
}

# ── can_grant — the mutation-time gate (jinbe calls this) ───────────────────
# A legal target is a non-global group whose services fit inside the target org's
# bundle (group_in_org_bundle). Given that, authority comes in two tiers:
#   A. delegated org admin — holds the org-admin FLAG for THIS org (manageable_orgs
#      = the `org_admins` flag + own-org membership). Authority is POSITIONAL: NO
#      per-service containment against the actor's own permissions is required —
#      the ceiling is the org's BUNDLE. This grants "up to service-admin within
#      the bundle".
#   B. service-wildcard admin — holds "*" in EVERY service the group spans (a
#      global super_admin, or a service admin resolving to "*"). No org
#      membership required; fail-closed for multi-service (a "*" in only one of
#      the group's services is not enough).
# Both tiers require group_in_org_bundle. Multi-service groups outside the bundle
# and global groups are never grantable here — for ANYONE, including super_admins
# going through the org endpoint (they still cannot grant a global group, nor the
# empty-binding `org_admins` flag itself, this way).
default can_grant = false

# Tier A — delegated org admin (org-admin FLAG + bundle; positional authority).
# manageable_orgs already requires the flag + own-org membership, so an org admin
# may grant any bundle-legal group to a user in that org WITHOUT holding the
# group's perms themselves. group_in_org_bundle is the ceiling (non-global,
# services ⊆ bundle) → never global/super_admin, never cross-bundle.
can_grant {
	group_in_org_bundle
	manageable_orgs[input.target_org]
}

# Tier B — service-wildcard admin ("*" in EVERY service the group spans; no
# membership required — mirrors the legacy service-admin reach across all orgs in
# the service). Fail-closed for multi-service.
can_grant {
	group_in_org_bundle
	every svc, _ in data.bindings.groups[input.target_group] {
		actor_perms_in(svc)["*"]
	}
}

# ── assignable_groups — which groups the actor may assign (UI feed) ─────────
# Lock-step with can_grant Tier A: a group is assignable iff it is non-global,
# confers ≥1 perm, and every service it spans is within the actor's MANAGED bundle
# (managed_services — the union of the bundles of the orgs they administer via the
# flag). Authority is positional, so there is NO per-service permission
# containment: the feed lists every bundle-legal group up to service-admin. It
# never lists a global group, and never the empty-binding `org_admins` flag itself
# (0 perms → excluded by count(gp) > 0), so the feed can never offer a
# peer-promotion to org admin.
assignable_groups[g] {
	group_def := data.bindings.groups[g]
	not group_has_global(g)
	gp := perms_of_group(g)
	count(gp) > 0
	every svc, _ in group_def {
		managed_services[svc]
	}
}
