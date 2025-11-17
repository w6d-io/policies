### Rego rules for Opal RBAC authorization

# DATA set

# {
#     "bindings": {
#         "emails": {
#             "admin@w6d.io": [
#                 "admin"
#             ],
#             "bash62@protonmail.com": [
#                 "developer"
#             ]
#         },
#         "group_membership": {
#             "bash62@protonmail.com": [
#                 "engineering"
#             ]
#         },
#         "groups": {
#             "engineering": [
#                 "dev"
#             ]
#         }
#     },
#     "roles": {
#         "admin": [
#             "*"
#         ],
#         "dev": [
#             "docs:read"
#         ],
#         "developer": [
#             "docs:read"
#         ]
#     },
#     "route_map": {
#         "jinbe": {
#             "rules": [
#                 {
#                     "method": "GET",
#                     "path": "/docs",
#                     "permission": "docs:read"
#                 },
#                 {
#                     "method": "GET",
#                     "path": "/public/:any*",
#                     "permission": null
#                 },
#                 {
#                     "method": "POST",
#                     "path": "/admin",
#                     "permission": "admin:write"
#                 }
#             ]
#         }
#     }
# }


# INPUTS TEST
# {
#     "input": {
#         "action": "GET",
#         "app": "jinbe",
#         "email": "admin@w6d.io",
#         "object": "/docs",
#         "sub": "2272ecf1-cfb7-4198-8495-c498323e9c1f"
#     }
# }

# {
#     "input": {
#         "action": "GET",
#         "app": "jinbe",
#         "email": "bash62@protonmail.com",
#         "object": "/docs",
#         "sub": "2272ecf1-cfb7-4198-8495-c498323e9c1f"
#     }
# }



package opal

default allow = false

# Debug: Check if email exists in bindings
debug_email_exists = true if {
    data.bindings.emails[input.email]
}



# Allow if user exist




debug_direct_roles = roles if {
    roles = data.bindings.emails[input.email]
}

# Debug: Check group membership
debug_user_groups = groups if {
    groups = data.bindings.group_membership[input.email]
}

# Debug: Check group roles
debug_group_roles = roles if {
    groups = data.bindings.group_membership[input.email]
    group = groups[_]
    roles = data.bindings.groups[group]
}

# Debug: Check route map
debug_route_map = routes if {
    routes = data.route_map[input.app].rules
}

# Debug: Check path matching
debug_path_match = result if {
    pattern = "/public/:any*"
    request_path = "/public/zefz"
    contains(pattern, ":any*")
    prefix = trim_suffix(pattern, ":any*")
    result = startswith(request_path, prefix)
}

# Get all user roles efficiently
user_roles contains role if {
    # From direct email bindings
    roles = data.bindings.emails[input.email]
    role = roles[_]
}

user_roles contains role if {
    # From group memberships
    groups = data.bindings.group_membership[input.email]
    group = groups[_]
    roles = data.bindings.groups[group]
    role = roles[_]
}

# Check if user is admin
is_admin if {
    "admin" = user_roles[_]
}

# Find matching route rules
matching_rules contains rule if {
    route_config = data.route_map[input.app]
    rule = route_config.rules[_]
    rule.method = input.action
    path_matches(rule.path, input.object)
}

# Path matching (exact)
path_matches(pattern, request_path) if {
    pattern = request_path
}

# Path matching (:any* suffix wildcard)
path_matches(pattern, request_path) if {
    contains(pattern, ":any*")
    prefix = trim_suffix(pattern, ":any*")
    startswith(request_path, prefix)
}

# Check if user has specific permission
has_permission(_) if {
    role = user_roles[_]
    perms = data.roles[role]
    perm = perms[_]
    perm = "*"
}

has_permission(permission) if {
    role = user_roles[_]
    perms = data.roles[role]
    perm = perms[_]
    permission = perm
}

# Main authorization logic

# Admin can do everything
allow if {
    is_admin
}

# Public routes (no permission required)
allow if {
    rule = matching_rules[_]
    rule.permission = null
}

# Permission-protected routes
allow if {
    rule = matching_rules[_]
    rule.permission != null
    has_permission(rule.permission)
}
