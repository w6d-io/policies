package rbac

import future.keywords.every


default allow = false

# --- 1. USER ROLE AGGREGATION ---
# From direct email bindings
user_roles[role] {
    roles := data.bindings.emails[input.email]
    role := roles[_]
}

# From group memberships
user_roles[role] {
    groups := data.bindings.group_membership[input.email]
    group := groups[_]
    roles := data.bindings.groups[group]
    role := roles[_]
}

# --- 2. USER PERMISSION AGGREGATION ---
user_permissions[perm] {
    role := user_roles[_]
    perms := data.roles[role]
    perm := perms[_]
}

# --- 3. REQUEST ROUTE MATCHING ---
matching_rules[rule] {
    route_config := data.route_map[input.app]
    rule := route_config.rules[_]
    rule.method == input.action
    path_matches(rule.path, input.object)
}

# Helper function for path matching (exact match)
path_matches(pattern, request_path) {
    pattern == request_path
}

# Helper function for path matching (:any* suffix wildcard)
path_matches(pattern, request_path) {
    contains(pattern, ":any*")
    prefix := trim_suffix(pattern, ":any*")
    startswith(request_path, prefix)
}

# Helper function for path matching with :param segments
# Matches patterns like /api/clusters/:id against /api/clusters/abc123
path_matches(pattern, request_path) {
    contains(pattern, ":")
    not contains(pattern, ":any*")
    pattern_parts := split(pattern, "/")
    path_parts := split(request_path, "/")
    count(pattern_parts) == count(path_parts)
    all_parts_match(pattern_parts, path_parts)
}

# Check all path segments match (either exact or :param wildcard)
all_parts_match(pattern_parts, path_parts) {
    count(pattern_parts) == count(path_parts)
    every i, _ in pattern_parts {
        part_matches(pattern_parts[i], path_parts[i])
    }
}

# A segment matches if pattern starts with : (parameter placeholder)
part_matches(pattern_part, path_part) {
    startswith(pattern_part, ":")
}

# A segment matches if exact string match
part_matches(pattern_part, path_part) {
    not startswith(pattern_part, ":")
    pattern_part == path_part
}

# --- 4. UNIFIED PERMISSION CHECK ---
user_has_permission(permission) {
    user_permissions[permission]
}

user_has_permission(_) {
    user_permissions["*"]
}

# --- 5. USER INFO ENDPOINT ---
# Returns user's resolved roles and permissions for /api/whoami
user_info = info {
    info := {
        "email": input.email,
        "groups": data.bindings.group_membership[input.email],
        "roles": user_roles,
        "permissions": user_permissions
    }
}

# Fallback when user not found in bindings
user_info = info {
    not data.bindings.group_membership[input.email]
    not data.bindings.emails[input.email]
    info := {
        "email": input.email,
        "groups": [],
        "roles": set(),
        "permissions": set()
    }
}

# --- 6. CONSOLIDATED ALLOW LOGIC ---
# Allow if route has null permission (public)
allow {
    rule := matching_rules[_]
    rule.permission == null
}

# Allow if user has required permission
allow {
    rule := matching_rules[_]
    required_perm := rule.permission
    required_perm != null
    user_has_permission(required_perm)
}

