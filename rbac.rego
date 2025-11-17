package rbac # <-- RECOMMENDATION: Match your file name

default allow := false

# --- 1. USER ROLE AGGREGATION ---
user_roles contains role if {
	# From direct email bindings
	roles := data.bindings.emails[input.email] # <-- FIX
	role := roles[_]
}

user_roles contains role if {
	# From group memberships
	groups := data.bindings.group_membership[input.email] # <-- FIX
	group := groups[_]
	roles := data.bindings.groups[group]
	role := roles[_]
}

# --- 2. USER PERMISSION AGGREGATION ---
user_permissions contains perm if {
	role := user_roles[_]
	perms := data.roles[role]
	perm := perms[_]
}

# --- 3. REQUEST ROUTE MATCHING ---
matching_rules contains rule if {
	route_config := data.route_map[input.app] # <-- FIX
	rule := route_config.rules[_]
	rule.method = input.action # <-- FIX
	path_matches(rule.path, input.object) # <-- FIX
}

# Helper function for path matching (exact).
path_matches(pattern, request_path) if {
	pattern = request_path
}

# Helper function for path matching (:any* suffix wildcard).
path_matches(pattern, request_path) if {
	contains(pattern, ":any*")
	prefix := trim_suffix(pattern, ":any*")
	startswith(request_path, prefix)
}

# --- 4. UNIFIED PERMISSION CHECK ---
user_has_permission(permission) if {
	user_permissions[permission]
}

user_has_permission(_) if {
	user_permissions["*"]
}

# --- 5. CONSOLIDATED ALLOW LOGIC ---
allow if {
	rule := matching_rules[_]
	rule.permission = null
}

allow if {
	rule := matching_rules[_]
	required_perm := rule.permission
	user_has_permission(required_perm)
}

