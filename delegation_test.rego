package rbac.delegation_test

import data.rbac.delegation

# ── Fixtures (per-org admin roster model) ─────────────────────────────────────
# Org-admin is a PER-ORG roster: data.org_admin_map[orgId] = [admin emails].
# A user administers an org iff they are on ITS roster AND belong to it.
groups_fx := {
	"jinbe-viewers": {"jinbe": ["viewer"]},
	"jinbe-editors": {"jinbe": ["editor"]},
	"jinbe-admins": {"jinbe": ["admin"]},
	"kuma-viewers": {"kuma": ["viewer"]},
	"multi-svc": {"jinbe": ["viewer"], "kuma": ["viewer"]},
	"super_admins": {"global": ["super_admin"]},
}

roles_fx := {
	"global": {"super_admin": ["*"]},
	"jinbe": {
		"viewer": ["users:read"],
		"editor": ["users:read", "users:delete"],
		"admin": ["*"],
	},
	"kuma": {"viewer": ["users:read"]},
}

# Org-admin is NOT a group — these are just the actors' base RBAC groups.
gm_fx := {
	"member@a.io": ["jinbe-viewers"],
	"svcadmin@a.io": ["jinbe-admins"], # jinbe "*" (tier B), no org
}

uorg_fx := {
	"adminA@a.io": ["org_a"],           # member of org_a
	"member@a.io": ["org_a"],
	"svcadmin@a.io": [],
	"multi@a.io": ["org_a", "org_b"],   # member of BOTH orgs
}

# array-valued bundles
osm_fx := {"org_a": ["jinbe"], "org_b": ["kuma"]}

# PER-ORG ROSTER: adminA administers org_a; multi administers ONLY org_b (though
# they also belong to org_a). member is on no roster.
oam_fx := {
	"org_a": ["adminA@a.io"],
	"org_b": ["multi@a.io"],
}

grant(email, group, org) = decision {
	decision := delegation.can_grant with input as {"actor": {"email": email}, "target_group": group, "target_org": org}
		with data.bindings.group_membership as gm_fx
		with data.bindings.groups as groups_fx
		with data.roles as roles_fx
		with data.bindings.user_organizations as uorg_fx
		with data.org_service_map as osm_fx
		with data.org_admin_map as oam_fx
}

# ── can_grant — per-org admin ────────────────────────────────────────────────

test_admin_grants_bundle_group_in_rostered_org {
	grant("adminA@a.io", "jinbe-viewers", "org_a")
}

test_admin_grants_service_admin_within_bundle {
	grant("adminA@a.io", "jinbe-admins", "org_a")
}

test_admin_grants_perm_they_do_not_personally_hold {
	grant("adminA@a.io", "jinbe-editors", "org_a")
}

test_admin_denied_cross_bundle {
	not grant("adminA@a.io", "kuma-viewers", "org_a")
}

test_admin_denied_global_group {
	not grant("adminA@a.io", "super_admins", "org_a")
}

test_member_not_on_roster_denied {
	not grant("member@a.io", "jinbe-viewers", "org_a")
}

# THE PER-ORG CASE: multi belongs to org_a AND org_b but is rostered ONLY for
# org_b. They may grant in org_b (kuma bundle)...
test_multi_admin_grants_in_rostered_org {
	grant("multi@a.io", "kuma-viewers", "org_b")
}

# ...but NOT in org_a, where they are a plain member (not on that roster).
test_multi_admin_denied_in_unrostered_org {
	not grant("multi@a.io", "jinbe-viewers", "org_a")
}

# ── tier B: service-wildcard admin ("*", no roster, no membership) ────────────
test_svc_wildcard_admin_grants_same_service {
	grant("svcadmin@a.io", "jinbe-viewers", "org_a")
}

test_svc_wildcard_admin_denied_multi_service {
	not grant("svcadmin@a.io", "multi-svc", "org_a")
}

test_svc_wildcard_admin_denied_global {
	not grant("svcadmin@a.io", "super_admins", "org_a")
}

# ── manageable_orgs (per-org roster ∩ membership) ─────────────────────────────
mo(email) = orgs {
	orgs := delegation.manageable_orgs with input as {"actor": {"email": email}}
		with data.bindings.group_membership as gm_fx
		with data.bindings.groups as groups_fx
		with data.roles as roles_fx
		with data.bindings.user_organizations as uorg_fx
		with data.org_service_map as osm_fx
		with data.org_admin_map as oam_fx
}

test_manageable_orgs_rostered_admin {
	mo("adminA@a.io") == {"org_a"}
}

# per-org: multi administers ONLY org_b, not org_a (which they merely belong to)
test_manageable_orgs_per_org {
	mo("multi@a.io") == {"org_b"}
}

test_manageable_orgs_excludes_non_admin_member {
	mo("member@a.io") == set()
}

test_manageable_orgs_excludes_svc_admin {
	mo("svcadmin@a.io") == set()
}

# ── assignable_groups (UI feed, lock-step with tier A) ────────────────────────
assignable(email) = groups {
	groups := delegation.assignable_groups with input as {"actor": {"email": email}}
		with data.bindings.group_membership as gm_fx
		with data.bindings.groups as groups_fx
		with data.roles as roles_fx
		with data.bindings.user_organizations as uorg_fx
		with data.org_service_map as osm_fx
		with data.org_admin_map as oam_fx
}

test_assignable_lists_bundle_groups {
	g := assignable("adminA@a.io")
	g["jinbe-viewers"]
	g["jinbe-admins"]
	not g["kuma-viewers"] # kuma not in org_a bundle
	not g["super_admins"] # global excluded
}

test_assignable_empty_for_non_admin {
	assignable("member@a.io") == set()
}
