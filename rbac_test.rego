package rbac_test

import data.rbac

# ── Fixtures ─────────────────────────────────────────────────────────────────
# jinbe owns the centralised org-user route; it carries BOTH the legacy admin
# rule and the delegation org:manage_users rule. `settings` carries a NON-
# management permission to exercise the org-admin capability ceiling.
rm := {"jinbe": {"rules": [
	{"method": "GET", "path": "/api/organizations/:organizationId/users", "permission": "admin:read"},
	{"method": "GET", "path": "/api/organizations/:organizationId/users", "permission": "org:manage_users"},
	{"method": "GET", "path": "/api/organizations/:organizationId/settings", "permission": "org:billing"},
	{"method": "GET", "path": "/api/clusters", "permission": "clusters:read"},
]}}

roles := {
	"global": {"super_admin": ["*"]},
	"jinbe": {"admin": ["*"], "viewer": ["databases:read"]},
	"kuma": {"org_admin": ["org:manage_users", "users:read"], "viewer": ["read"]},
}

groups := {
	"super_admins": {"global": ["super_admin"]},
	"admins": {"jinbe": ["admin"]},
	"kuma-org-admins": {"kuma": ["org_admin"]},
}

gm := {
	"super@x.io": ["super_admins"],
	"jadmin@x.io": ["admins"],
	"orgadmin@x.io": ["kuma-org-admins"],
	"rosteradmin@x.io": [], # org-admin via the roster, not a group
	"memberonly@x.io": [], # member of org_k but NOT on its roster
	"nobody@x.io": [],
}

osm := {"org_k": "kuma", "org_j": "jinbe"}

# rosteradmin + memberonly both belong to org_k; only rosteradmin is on its roster.
uorg := {
	"rosteradmin@x.io": ["org_k"],
	"memberonly@x.io": ["org_k"],
}

# PER-ORG admin roster: org_k's admins = [rosteradmin]. memberonly is a member, not
# an admin. org_j has no roster.
oam := {"org_k": ["rosteradmin@x.io"]}

decide(email, action, object) = a {
	a := rbac.allow with input as {"email": email, "action": action, "object": object}
		with data.route_map as rm
		with data.roles as roles
		with data.bindings.group_membership as gm
		with data.bindings.groups as groups
		with data.bindings.user_organizations as uorg
		with data.org_service_map as osm
		with data.org_admin_map as oam
}

# ── legacy per-service org-admin (via clause 4) ──────────────────────────────

# kuma org admin passes the gateway for a kuma org's mgmt route (org:manage_users
# resolved in kuma — the org's mapped service)
test_org_admin_allowed_on_own_service_org {
	decide("orgadmin@x.io", "GET", "/api/organizations/org_k/users")
}

# ...but NOT for an org mapped to a service they don't administer (jinbe)
test_org_admin_denied_other_service_org {
	not decide("orgadmin@x.io", "GET", "/api/organizations/org_j/users")
}

# unmapped org → no service → fail closed
test_unmapped_org_denied {
	not decide("orgadmin@x.io", "GET", "/api/organizations/org_unmapped/users")
}

# ── per-org admin ROSTER clause ──────────────────────────────────────────────

# a user on org_k's roster reaches org_k's mgmt route
test_roster_admin_allowed_own_org {
	decide("rosteradmin@x.io", "GET", "/api/organizations/org_k/users")
}

# ...but NOT an org they are not on the roster for / do not belong to
test_roster_admin_denied_other_org {
	not decide("rosteradmin@x.io", "GET", "/api/organizations/org_j/users")
}

# PER-ORG: a plain member of org_k who is NOT on its roster is denied — membership
# alone is not admin.
test_member_not_on_roster_denied {
	not decide("memberonly@x.io", "GET", "/api/organizations/org_k/users")
}

# the roster confers ONLY membership-management perms — a non-management route on
# their OWN org (org:billing) is NOT granted (ceiling)
test_roster_admin_denied_non_mgmt_perm {
	not decide("rosteradmin@x.io", "GET", "/api/organizations/org_k/settings")
}

# the roster confers no service permissions at all — a non-org service route denies
test_roster_admin_no_service_perms {
	not decide("rosteradmin@x.io", "GET", "/api/clusters")
}

# a caller who is neither rostered nor a member is denied
test_non_admin_denied {
	not decide("nobody@x.io", "GET", "/api/organizations/org_k/users")
}

# ── regressions: existing allow paths still work ────────────────────────────

# global super_admin bypasses via the "*" clause
test_super_admin_allowed {
	decide("super@x.io", "GET", "/api/organizations/org_k/users")
}

# service (jinbe) admin with jinbe.admin=["*"] allowed via the "*" clause
test_service_wildcard_admin_allowed {
	decide("jadmin@x.io", "GET", "/api/organizations/org_k/users")
}

# unknown route → denied (no matching rule; additive clause needs a rule).
test_unknown_route_denied {
	not decide("nobody@x.io", "GET", "/api/nonexistent")
}
