package app.rbac

default allow = false

# Check if the input.action is in a list
action_in(list, a) {
  list[_] == a
}

# User has role either directly or via groups
user_has_role(role) {
  data.app.rbac.user_roles[input.sub][role]
} else {
  some g
  g := input.groups[_]
  data.app.rbac.group_roles[g][role]
}

# Permission match for a role:
# - app equals input.app
# - object regex matches input.object (e.g. "^/api/projects/[^/]+$")
# - action is allowed
role_allows(role) {
  some p
  p := data.app.rbac.role_permissions[role][_]
  p.app == input.app
  regex.match(p.object_re, input.object)
  action_in(p.actions, input.action)
}

allow {
  some r
  user_has_role(r)
  role_allows(r)
}

