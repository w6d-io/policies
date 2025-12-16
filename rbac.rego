package rbac

import future.keywords.every

default allow = false

# --- 1. USER ROLE AGGREGATION (per service) ---

# Get user's roles for the current app/service
# From global roles (apply to all services)
user_roles_for_app[role] {
    groups := data.bindings.group_membership[input.email]
    group := groups[_]
    group_roles := data.bindings.groups[group]
    global_roles := group_roles["global"]
    role := global_roles[_]
}

# From service-specific roles
user_roles_for_app[role] {
    groups := data.bindings.group_membership[input.email]
    group := groups[_]
    group_roles := data.bindings.groups[group]
    service_roles := group_roles[input.app]
    role := service_roles[_]
}

# From direct email bindings (global)
user_roles_for_app[role] {
    email_roles := data.bindings.emails[input.email]
    global_roles := email_roles["global"]
    role := global_roles[_]
}

# From direct email bindings (service-specific)
user_roles_for_app[role] {
    email_roles := data.bindings.emails[input.email]
    service_roles := email_roles[input.app]
    role := service_roles[_]
}

# --- 2. USER PERMISSION AGGREGATION (per service) ---

# Get permissions from global roles
user_permissions[perm] {
    role := user_roles_for_app[_]
    perms := data.roles.global[role]
    perm := perms[_]
}

# Get permissions from service-specific roles
user_permissions[perm] {
    role := user_roles_for_app[_]
    perms := data.roles[input.app][role]
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

# Wildcard permission (admin has all)
user_has_permission(_) {
    user_permissions["*"]
}

# --- 5. USER INFO ENDPOINT ---
# Returns user's resolved roles and permissions for the current app
# Call with: POST /v1/data/rbac/user_info {"input": {"email": "...", "app": "jinbe"}}

user_info = info {
    data.bindings.group_membership[input.email]
    info := {
        "email": input.email,
        "app": input.app,
        "groups": data.bindings.group_membership[input.email],
        "roles": user_roles_for_app,
        "permissions": user_permissions
    }
}

# Fallback when user not found
user_info = info {
    not data.bindings.group_membership[input.email]
    not data.bindings.emails[input.email]
    info := {
        "email": input.email,
        "app": input.app,
        "groups": [],
        "roles": set(),
        "permissions": set()
    }
}

# --- 6. ALL APPS USER INFO ---
# Returns user's roles across ALL services (useful for frontend)
# Call with: POST /v1/data/rbac/user_info_all {"input": {"email": "..."}}

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
        "roles_by_app": user_roles_all_apps
    }
}

user_info_all = info {
    not data.bindings.group_membership[input.email]
    info := {
        "email": input.email,
        "groups": [],
        "roles_by_app": {}
    }
}

# --- 7. CONSOLIDATED ALLOW LOGIC ---
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

