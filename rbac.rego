package opal

import future.keywords.in

default allow := false

# Set of user roles for the input user
user_roles[role] {
  email := input.email
  roles := data.bindings.emails[email]
  role := roles[_]
}

# Admin role has wildcard access
is_admin {
  "admin" in user_roles
}

# Set of matching route rules
matching_rule[rule] {
  project := input.app
  route_config := data.route_map[project]
  rule := route_config.rules[_]
  rule.method == input.action
  path_matches(rule.path, input.object)
}

# Path matching (exact)
path_matches(pattern, request_path) {
  pattern == request_path
}

# Path matching (:any* suffix wildcard)
path_matches(pattern, request_path) {
  contains(pattern, ":any*")
  prefix := trim_suffix(pattern, ":any*")
  startswith(request_path, prefix)
}

# Main authorization logic

# Admin can do everything
allow {
  is_admin
}

# Route requires no permission
allow {
  rule := matching_rule[_]
  rule.permission == null
}

# Route requires a permission; user must have it
allow {
  rule := matching_rule[_]
  rule.permission != null
  user_has_permission(rule.permission)
}

# Permission checks
user_has_permission(permission) {
  role := user_roles[_]
  perms := data.roles.roles[role]
  perms[_] == "*"
}

user_has_permission(permission) {
  role := user_roles[_]
  perms := data.roles.roles[role]
  permission == perms[_]
}

