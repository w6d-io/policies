package opal

default allow = false

# Check if user is admin
is_admin {
    roles = data.bindings.emails[input.email]
    roles[_] = "admin"
}

is_admin {
    groups = data.bindings.group_membership[input.email]
    group = groups[_]
    roles = data.bindings.groups[group]
    roles[_] = "admin"
}

# Check if route is public
is_public_route {
    route_config = data.route_map[input.app]
    rule = route_config.rules[_]
    rule.method = input.action
    rule.path = input.object
    rule.permission = null
}

is_public_route {
    route_config = data.route_map[input.app]
    rule = route_config.rules[_]
    rule.method = input.action
    contains(rule.path, ":any*")
    prefix = trim_suffix(rule.path, ":any*")
    startswith(input.object, prefix)
    rule.permission = null
}

# Check if user has permission for route
has_route_permission {
    route_config = data.route_map[input.app]
    rule = route_config.rules[_]
    rule.method = input.action
    rule.path = input.object
    rule.permission != null
    user_has_permission(rule.permission)
}

has_route_permission {
    route_config = data.route_map[input.app]
    rule = route_config.rules[_]
    rule.method = input.action
    contains(rule.path, ":any*")
    prefix = trim_suffix(rule.path, ":any*")
    startswith(input.object, prefix)
    rule.permission != null
    user_has_permission(rule.permission)
}

# Check if user has specific permission
user_has_permission(_) {
    roles = data.bindings.emails[input.email]
    role = roles[_]
    perms = data.roles[role]
    perms[_] = "*"
}

user_has_permission(permission) {
    roles = data.bindings.emails[input.email]
    role = roles[_]
    perms = data.roles[role]
    perms[_] = permission
}

user_has_permission(_) {
    groups = data.bindings.group_membership[input.email]
    group = groups[_]
    roles = data.bindings.groups[group]
    role = roles[_]
    perms = data.roles[role]
    perms[_] = "*"
}

user_has_permission(permission) {
    groups = data.bindings.group_membership[input.email]
    group = groups[_]
    roles = data.bindings.groups[group]
    role = roles[_]
    perms = data.roles[role]
    perms[_] = permission
}

# Final allow rule
allow {
    is_admin
}

allow {
    is_public_route
}

allow {
    has_route_permission
}
