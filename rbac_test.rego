package rbac_test

import data.rbac

# ──────────────────────────────────────────────────────────────────────
# Tests for the multi-organization (Path 3 hybrid) gate added in
# rbac.rego.
#
# Tests substitute `data.bindings.*`, `data.roles.*` and
# `data.route_map.*` individually rather than via `with data as ...`
# on the whole document — whole-document substitution trips OPA's
# recursion detector (https://github.com/open-policy-agent/opa/issues/4282)
# because the compiler cannot statically prove the test rule is not
# itself part of the replacement. Per-key substitution is the pattern
# recommended in the OPA test docs.
# ──────────────────────────────────────────────────────────────────────

# UUIDs used across the test cases (opaque to the policy).
org_a := "11111111-1111-1111-1111-111111111111"
org_b := "22222222-2222-2222-2222-222222222222"
org_c := "33333333-3333-3333-3333-333333333333"

# Shared fixture pieces. Top-level constants so the test bodies stay
# compact, and so per-key `with data.X as fixture_X` substitution works
# without the compiler flagging recursion.
group_membership := {
  "alice@example.org":    ["readers"],
  "bob@example.org":      ["readers"],
  "carol@example.org":    ["admins"],
  "legacy@example.org":   ["readers"],
  "noorg@example.org":    ["readers"],
}

groups := {
  "readers": {"jinbe": ["reader"]},
  "admins":  {"global": ["super_admin"]},
}

user_organizations := {
  "alice@example.org": ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"],
  "bob@example.org":   ["22222222-2222-2222-2222-222222222222"],
  "carol@example.org": ["11111111-1111-1111-1111-111111111111"],
  "noorg@example.org": [],
}

user_organization_primary := {
  "legacy@example.org": "11111111-1111-1111-1111-111111111111",
}

roles := {
  "global": {"super_admin": ["*"]},
  "jinbe":  {"reader": ["clusters:read"]},
}

route_map := {
  "jinbe": {
    "rules": [
      {"method": "GET",  "path": "/api/clusters",        "permission": "clusters:read"},
      {"method": "GET",  "path": "/api/public/health"},
      {"method": "POST", "path": "/api/admin/users"},
    ],
  },
}

# Variant for the "permission missing" decision_reason case — the
# only declared rule needs a permission `noorg@example.org` does not hold.
admin_only_route_map := {
  "jinbe": {
    "rules": [
      {"method": "POST", "path": "/api/admin/secret", "permission": "admin:write"},
    ],
  },
}

# ──────────────────────────────────────────────────────────────────────
# Helper: user_in_org
# ──────────────────────────────────────────────────────────────────────

test_user_in_org_multi_org_membership {
  rbac.user_in_org("alice@example.org", org_a)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary

  rbac.user_in_org("alice@example.org", org_b)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
}

test_user_in_org_rejects_non_member {
  not rbac.user_in_org("bob@example.org", org_a)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
}

test_user_in_org_unknown_email {
  not rbac.user_in_org("ghost@example.org", org_a)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
}

test_user_in_org_legacy_single_org_pointer {
  # legacy@example.org has no entry in user_organizations but is pinned
  # to org_a via the legacy single-org pointer — must still pass.
  rbac.user_in_org("legacy@example.org", org_a)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
}

test_user_in_org_legacy_pointer_rejects_other_org {
  not rbac.user_in_org("legacy@example.org", org_b)
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
}

# ──────────────────────────────────────────────────────────────────────
# Allow logic — super-admin wildcard bypass
# ──────────────────────────────────────────────────────────────────────

test_allow_super_admin_without_org_input {
  rbac.allow
    with input as {
      "email":  "carol@example.org",
      "object": "/api/some/random/path/never/declared",
      "action": "GET",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_allow_super_admin_with_unrelated_org_id {
  # Super-admin holds the "*" wildcard — the tenant gate is bypassed
  # even when the request targets an org the admin is not a member of.
  rbac.allow
    with input as {
      "email":           "carol@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_c,  # carol is in org_a only
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

# ──────────────────────────────────────────────────────────────────────
# Allow logic — tenant gate, non-admin paths
# ──────────────────────────────────────────────────────────────────────

test_allow_when_route_permission_and_org_match {
  rbac.allow
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_deny_when_route_permission_but_org_mismatch {
  # alice holds clusters:read but is not in org_c
  not rbac.allow
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_c,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_deny_when_method_does_not_match_any_rule {
  # DELETE /api/clusters is not declared in route_map → no matching
  # rule → falls back to `not_found` even though the user is in the
  # org. Pins that the tenant gate doesn't accidentally allow.
  not rbac.allow
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "DELETE",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

# ──────────────────────────────────────────────────────────────────────
# Allow logic — public endpoints (no permission on the rule)
# ──────────────────────────────────────────────────────────────────────

test_allow_public_route_without_org_input {
  rbac.allow
    with input as {
      "email":  "noorg@example.org",
      "object": "/api/public/health",
      "action": "GET",
      "app":    "jinbe",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_allow_public_route_with_matching_org {
  rbac.allow
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/public/health",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_deny_public_route_when_org_mismatch {
  # Even a public route is denied if the caller is not a member of
  # the tenant the request targets. Prevents a logged-in user of
  # tenant A from triggering tenant B's public endpoints by spoofing
  # X-Tenant-Id.
  not rbac.allow
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/public/health",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_c,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

# ──────────────────────────────────────────────────────────────────────
# Backward compatibility — no input.organization_id
# ──────────────────────────────────────────────────────────────────────

test_backcompat_no_org_input_still_allows_permission_match {
  # Pre-multi-org callers don't send organization_id at all. The
  # tenant gate must default to passing for these requests so
  # existing single-tenant deployments continue to work.
  rbac.allow
    with input as {
      "email":  "alice@example.org",
      "object": "/api/clusters",
      "action": "GET",
      "app":    "jinbe",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_backcompat_no_org_input_still_denies_unknown_route {
  not rbac.allow
    with input as {
      "email":  "alice@example.org",
      "object": "/api/does/not/exist",
      "action": "GET",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

# ──────────────────────────────────────────────────────────────────────
# Legacy single-org pointer
# ──────────────────────────────────────────────────────────────────────

test_legacy_single_org_user_can_access_their_org {
  rbac.allow
    with input as {
      "email":           "legacy@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_legacy_single_org_user_denied_for_other_org {
  not rbac.allow
    with input as {
      "email":           "legacy@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_b,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

# ──────────────────────────────────────────────────────────────────────
# decision_reason
# ──────────────────────────────────────────────────────────────────────

test_decision_reason_ok_on_allow {
  rbac.decision_reason == "ok"
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_decision_reason_not_found_for_unknown_route {
  rbac.decision_reason == "not_found"
    with input as {
      "email":  "alice@example.org",
      "object": "/api/does/not/exist",
      "action": "GET",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_decision_reason_forbidden_org_when_permission_held_but_wrong_tenant {
  rbac.decision_reason == "forbidden_org"
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_c,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map
}

test_decision_reason_forbidden_when_route_matches_but_permission_missing {
  # noorg@example.org is in `readers` (perms = clusters:read) — uses
  # the admin-only route_map so the single declared rule needs a
  # permission the user does not hold.
  rbac.decision_reason == "forbidden"
    with input as {
      "email":  "noorg@example.org",
      "object": "/api/admin/secret",
      "action": "POST",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as admin_only_route_map
}

# ──────────────────────────────────────────────────────────────────────
# decision payload shape
# ──────────────────────────────────────────────────────────────────────

test_decision_payload_includes_organizations_array {
  d := rbac.decision
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_a,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map

  d.allow == true
  d.organizations == [org_a, org_b]
  d.reason == "ok"
  count(d.groups) == 1
  d.groups[0] == "readers"
}

test_decision_payload_organizations_empty_when_user_has_none {
  d := rbac.decision
    with input as {
      "email":  "noorg@example.org",
      "object": "/api/public/health",
      "action": "GET",
      "app":    "jinbe",
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map

  d.organizations == []
}

test_decision_payload_organizations_present_even_when_denied {
  # The proxy may want to forward X-User-Organizations on a 403 too
  # so the SPA can re-render the org switcher. Verify the field is
  # populated regardless of allow verdict.
  d := rbac.decision
    with input as {
      "email":           "alice@example.org",
      "object":          "/api/clusters",
      "action":          "GET",
      "app":             "jinbe",
      "organization_id": org_c,
    }
    with data.bindings.group_membership as group_membership
    with data.bindings.groups as groups
    with data.bindings.user_organizations as user_organizations
    with data.bindings.user_organization_primary as user_organization_primary
    with data.roles as roles
    with data.route_map as route_map

  d.allow == false
  d.reason == "forbidden_org"
  d.organizations == [org_a, org_b]
}
