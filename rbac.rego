package app.rbac

default allow = false
default roles_for_user = []

# ---- locate maps regardless of nesting ----
roles_map := m { m := data.roles.roles } else { m := data.roles }
bindings_map := m { m := data.bindings.bindings } else { m := data.bindings }
users_map := um { um := bindings_map.users } else { um := bindings_map }
routes_map := rm { rm := data.routes.routes } else { rm := data.routes }

# ---- roles_for_user (array) ----
roles_for_user := rs {
  email := lower(input.email)
  um := users_map
  rs := um[email]
}

# ---- method match (ANY) ----
method_matches(m, methods) { methods[_] == "ANY" }
method_matches(m, methods) { lower(methods[_]) == lower(m) }

# ---- allow via wildcard ----
allow {
  rm := roles_map
  rtm := routes_map
  um := users_map
  email := lower(input.email)

  r := rtm[input.app][_]
  re_match(r.pattern, input.object)
  method_matches(input.action, r.methods)

  role := um[email][_]
  p := rm[role][_]
  p == "*"
}

# ---- allow via exact match ----
allow {
  rm := roles_map
  rtm := routes_map
  um := users_map
  email := lower(input.email)

  r := rtm[input.app][_]
  re_match(r.pattern, input.object)
  method_matches(input.action, r.methods)
  req := r.perms[_]

  role := um[email][_]
  p := rm[role][_]
  p == req
}
