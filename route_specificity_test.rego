package rbac_specificity_test

import data.rbac
import future.keywords.in

# ─── Fixtures ─────────────────────────────────────────────────────────────────
# One service, isolated path prefixes per relationship so each test is
# independent. Exercises exact / :param / :any* and every precedence pair.
rm_spec := {"svc": {"rules": [
	# (a) exact vs :param, same shape
	{"method": "GET", "path": "/a/exact", "permission": "p_a_exact"},
	{"method": "GET", "path": "/a/:id", "permission": "p_a_param"},
	# (b) :param vs :any* — param wins where both cover; any* covers deeper
	{"method": "GET", "path": "/b/:id", "permission": "p_b_param"},
	{"method": "GET", "path": "/b/:any*", "permission": "p_b_any"},
	# (c) exact vs :any*
	{"method": "GET", "path": "/c/exact", "permission": "p_c_exact"},
	{"method": "GET", "path": "/c/:any*", "permission": "p_c_any"},
	# (d) deep catch-all beats shallow catch-all
	{"method": "GET", "path": "/d/deep/:any*", "permission": "p_d_deep"},
	{"method": "GET", "path": "/d/:any*", "permission": "p_d_shallow"},
	# (e) among :param, more literal segments wins
	{"method": "GET", "path": "/e/fixed/:id", "permission": "p_e_fixed"},
	{"method": "GET", "path": "/e/:x/:id", "permission": "p_e_generic"},
	# (f) a PUBLIC catch-all must NOT expose a stricter exact route
	{"method": "GET", "path": "/f/secret", "permission": "p_f_secret"},
	{"method": "GET", "path": "/f/:any*"},
	# (g) one path declared with two permission rules — both kept (OR)
	{"method": "GET", "path": "/g/thing", "permission": "p_g_1"},
	{"method": "GET", "path": "/g/thing", "permission": "p_g_2"},
]}}

# Winning rule paths for a GET request (the surviving specificity tier).
won(object) = paths {
	mrs := rbac.matching_rules
		with input as {"app": "svc", "action": "GET", "object": object}
		with data.route_map as rm_spec
	paths := {r.path | some r in mrs}
}

# How many rules survived (to prove same-path multi-permission rules coexist).
won_count(object) = n {
	mrs := rbac.matching_rules
		with input as {"app": "svc", "action": "GET", "object": object}
		with data.route_map as rm_spec
	n := count(mrs)
}

# ─── Specificity selection ────────────────────────────────────────────────────
test_exact_beats_param { won("/a/exact") == {"/a/exact"} }

test_param_when_no_exact { won("/a/anything") == {"/a/:id"} }

test_param_beats_any { won("/b/x") == {"/b/:id"} }

test_any_when_path_too_deep_for_param { won("/b/x/y/z") == {"/b/:any*"} }

test_exact_beats_any { won("/c/exact") == {"/c/exact"} }

test_any_when_no_exact { won("/c/other") == {"/c/:any*"} }

test_deep_catchall_beats_shallow { won("/d/deep/x") == {"/d/deep/:any*"} }

test_shallow_catchall_when_not_deep { won("/d/other/x") == {"/d/:any*"} }

test_more_literal_param_wins { won("/e/fixed/9") == {"/e/fixed/:id"} }

test_generic_param_is_fallback { won("/e/other/9") == {"/e/:x/:id"} }

test_public_catchall_does_not_shadow_exact { won("/f/secret") == {"/f/secret"} }

test_public_catchall_covers_the_rest { won("/f/whatever") == {"/f/:any*"} }

test_same_path_two_permission_rules_both_kept { won_count("/g/thing") == 2 }

test_unknown_path_matches_nothing { won("/z/nope") == set() }

# ─── Security consequence: allow-level (loose wildcard cannot bypass) ──────────
roles_spec := {"svc": {
	"only_a_param": ["p_a_param"],
	"has_a_exact": ["p_a_exact"],
	"unrelated": ["read"],
}}

groups_spec := {
	"g_param": {"svc": ["only_a_param"]},
	"g_exact": {"svc": ["has_a_exact"]},
	"g_none": {"svc": ["unrelated"]},
}

gm_spec := {
	"param@x.io": ["g_param"],
	"exact@x.io": ["g_exact"],
	"none@x.io": ["g_none"],
}

allow_spec(email, object) = a {
	a := rbac.allow
		with input as {"email": email, "app": "svc", "action": "GET", "object": object}
		with data.route_map as rm_spec
		with data.roles as roles_spec
		with data.bindings.group_membership as gm_spec
		with data.bindings.groups as groups_spec
		# present-but-empty → the org→service gate's no-org fallback passes, so
		# these tests isolate the RBAC/specificity decision from the org gate.
		with data.bindings.user_organizations as {}
}

# THE FIX: holding only the :param permission no longer lets you through the
# exact route — the exact rule is the only one considered, so its permission is
# required. (Pre-fix this ALLOWED via the unioned /a/:id rule.)
test_param_perm_denied_on_exact_route { not allow_spec("param@x.io", "/a/exact") }

# ...but that same caller is allowed on a non-exact path (the :param fallback).
test_param_perm_allowed_on_param_path { allow_spec("param@x.io", "/a/other") }

# the exact-permission holder is allowed on the exact route.
test_exact_perm_allowed_on_exact_route { allow_spec("exact@x.io", "/a/exact") }

# a PUBLIC catch-all must not make a stricter exact route public: a caller with
# no relevant permission is denied on /f/secret even though /f/:any* is public.
test_public_catchall_does_not_expose_exact { not allow_spec("none@x.io", "/f/secret") }

# ...and /f/<anything-else> is genuinely public for that same caller.
test_public_catchall_still_public_elsewhere { allow_spec("none@x.io", "/f/other") }

# ─── MATCHER-EVASION / CANONICALIZATION (defense-in-depth: no path bypass) ────
# The exact rule is now stricter than its :param/:any* siblings, so a caller must
# not be able to dodge it into the looser wildcard by altering the path form.

won_m(method, object) = paths {
	mrs := rbac.matching_rules
		with input as {"app": "svc", "action": method, "object": object}
		with data.route_map as rm_spec
	paths := {r.path | some r in mrs}
}

# effective_app derived (no input.app) + canonicalization together.
won_noapp(object) = paths {
	mrs := rbac.matching_rules
		with input as {"action": "GET", "object": object}
		with data.route_map as rm_spec
	paths := {r.path | some r in mrs}
}

# trailing slash is canonicalized away → still the exact rule, NOT the catch-all.
test_trailing_slash_still_hits_exact { won("/a/exact/") == {"/a/exact"} }

test_trailing_double_slash_hits_exact { won("/a/exact//") == {"/a/exact"} }

# consecutive slashes collapse → exact.
test_double_slash_collapses_to_exact { won("/a//exact") == {"/a/exact"} }

# a :param path with a trailing slash stays in the :param tier (not the :any*).
test_trailing_slash_on_param { won("/b/x/") == {"/b/:id"} }

# dot-segments are non-canonical → canonical_object undefined → match NOTHING
# (fail-closed; never silently resolved to a parent, never the catch-all).
test_dotdot_matches_nothing { won("/a/exact/..") == set() }

test_dot_matches_nothing { won("/a/./exact") == set() }

# CASE IS NOT FOLDED (explicit, reviewed residual): an upper-case variant is a
# DIFFERENT path and drops to the :param tier. Upstreams MUST route paths
# case-sensitively so /a/EXACT can't serve the /a/exact resource. If an upstream
# ever routes case-insensitively, fold case for literal segments here.
test_case_is_not_folded_by_design { won("/a/EXACT") == {"/a/:id"} }

# canonicalization also applies when the service is derived (no explicit app).
test_canonicalization_with_derived_app { won_noapp("/a/exact/") == {"/a/exact"} }

# a method with no declared rule matches nothing (fail-closed 404).
test_wrong_method_matches_nothing { won_m("DELETE", "/a/exact") == set() }

# allow-level: the trailing-slash dodge is CLOSED — a caller holding only the
# loose :param permission is still denied on the exact route via /a/exact/.
test_trailing_slash_cannot_bypass_exact { not allow_spec("param@x.io", "/a/exact/") }

# ...and a dot-segment path denies even the legitimate exact-perm holder
# (fail-closed: the path is non-canonical, so nothing matches).
test_dot_segment_path_denied { not allow_spec("exact@x.io", "/a/exact/..") }
