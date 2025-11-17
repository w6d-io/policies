package opal



bar contains path if {

	path := data.route_map["jinbe"]["rules"]

}



default allow = false

# --- 1. USER ROLE AGGREGATION ---
# Get all roles assigned to the user, either directly or via groups.
# This logic is preserved from the original policy, as it is correct.
user_roles contains role if {
    # From direct email bindings
    roles := data.bindings.emails[input.email]
    role := roles[_]
}

user_roles contains role if {
    # From group memberships
    groups := data.bindings.group_membership[input.email]
    group := groups[_]
    roles := data.bindings.groups[group]
    role := roles[_]
}

# --- 2. USER PERMISSION AGGREGATION (NEW) ---
# This is the core optimization. We pre-compute the *entire set*
# of permissions the user has from all their roles.
user_permissions contains perm if {
    # Get one of the user's roles
    role := user_roles[_]
    # Get the list of permissions for that role
    perms := data.roles[role]
    # Iterate that list
    perm := perms[_]
}

# --- 3. REQUEST ROUTE MATCHING ---
# Find all rules in the route map that match the incoming request.
# This logic is preserved from the original policy.
matching_rules contains rule if {
    route_config := data.route_map[input.app]
    rule := route_config.rules[_]
    rule.method = input.action
    path_matches(rule.path, input.object)
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

# --- 4. UNIFIED PERMISSION CHECK (NEW & REPLACES FLAWED LOGIC) ---
# This single helper rule replaces both `is_admin` and `has_permission`.
# It elegantly handles exact permissions AND wildcard permissions.

# Case 1: Allow if the user has the *exact* permission required.
user_has_permission(permission) if {
    # Check if the required 'permission' exists in the set we built.
    user_permissions[permission]
}

# Case 2: Allow if the user has the global wildcard permission.
user_has_permission(_) if {
    # Check if the '*' permission exists in the set we built.
    user_permissions["*"]
}

# --- 5. CONSOLIDATED ALLOW LOGIC (OPTIMIZED) ---
# The main allow logic is now simple, clean, and unified.
# The special `is_admin` check is no longer needed.

# Rule 1: Allow requests for public routes (no permission defined).
allow if {
    rule := matching_rules[_]
    rule.permission = null
}

# Rule 2: Allow requests for protected routes if user has permission.
allow if {
    rule := matching_rules[_]
    required_perm := rule.permission
    # This single call now correctly checks both admins and regular users
    # thanks to the unified `user_has_permission` helper.
    user_has_permission(required_perm)
}
