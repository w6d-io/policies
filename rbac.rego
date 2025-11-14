package opal

default allow = false

# -------- helpers
path_matches_exact(rule) {
  rule.path == input.object
}

path_matches_prefix(rule) {
  contains(rule.path, ":any*")
  prefix := trim_suffix(rule.path, ":any*")
  startswith(input.object, prefix)
}

method_matches(rule) {
  upper(rule.method) == upper(input.action)
}

some_rule := route_config.rules[_] {
  route_config := data.route_map[input.app]
}

# -------- role/perm lookup (same as yours, just grouped)
is_admin {
  roles := data.bindings.emails[input.email]
  roles[_] == "admin"
}
is_admin {
  groups := data.bindings.group_membership[input.email]
  g := groups[_]
  roles := data.bindings.groups[g]
  roles[_] == "admin"
}

user_has_permission(_) {
  roles := data.bindings.emails[input.email]
  r := roles[_]
  perms := data.roles[r]
  perms[_] == "*"
}
user_has_permission(p) {
  roles := data.bindings.emails[input.email]
  r := roles[_]
  perms := data.roles[r]
  perms[_] == p
}
user_has_permission(_) {
  groups := data.bindings.group_membership[input.email]
  g := groups[_]
  roles := data.bindings.groups[g]
  r := roles[_]
  perms := data.roles[r]
  perms[_] == "*"
}
user_has_permission(p) {
  groups := data.bindings.group_membership[input.email]
  g := groups[_]
  roles := data.bindings.groups[g]
  r := roles[_]
  perms := data.roles[r]
  perms[_] == p
}

# -------- route eval
is_public_route {
  some_rule
  method_matches(some_rule)
  (path_matches_exact(some_rule) or path_matches_prefix(some_rule))
  some_rule.permission == null
}

has_route_permission {
  some_rule
  method_matches(some_rule)
  (path_matches_exact(some_rule) or path_matches_prefix(some_rule))
  some_rule.permission != null
  user_has_permission(some_rule.permission)
}

# -------- final decision
allow { is_admin }
allow { has_route_permission }
allow { is_public_route }

# -------- debug endpoint (query /v1/data/opal/why)
why := {
  "is_admin": is_admin,
  "is_public_route": is_public_route,
  "has_route_permission": has_route_permission,
  "input": input,
}

