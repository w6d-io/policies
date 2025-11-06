package app.rbac

default allow = false

# ---- helpers ----
norm_method(m) = upper(m)

norm_path(p) = out {
  p == "/"
  out := "/"
} else = out {
  endswith(p, "/")
  out := trim_suffix(p, "/")
} else = p

# Convert express-like paths (":id", optional trailing slash, simple wildcard ":any*") to regex
path_to_regex(path) = re {
  base := regex.replace(`([.+?^${}()|\[\]\\\\])`, path, `\\$1`)
  with_params := regex.replace(`:([^/*]+)\\*?`, base, `[^/]+`)
  # handle a trailing :param* (our simple splat)
  with_splat := regex.replace(`\\[\\^/\\]\\+\\$`, with_params, `.*`)
  re := "^" + with_splat + "/?$"
}

# ---- required perms from route_map only ----
required_perms := perms {
  svc := input.app
  some i
  rm := data.route_map[svc].rules[i]
  regex.match(path_to_regex(rm.path), norm_path(input.object))
  rm.method == norm_method(input.action)
  perms := (rm.permission == null) ? [] : [rm.permission]
}

# ---- role resolution: email-only (and optional id) ----
email_roles := rs {
  input.email != ""
  rs := data.bindings.emails[input.email]
} else := [] { true }

user_roles_direct := rs {
  rs := data.bindings.users[input.sub]
} else := [] { true }

effective_roles := roles {
  roles := array.concat(email_roles, user_roles_direct)
}

role_perms(role) = perms { perms := data.roles.roles[role] }

has_perm(p) {
  some r
  r := effective_roles[_]
  role_perms(r)[_] == "*"
} else {
  some r
  r := effective_roles[_]
  role_perms(r)[_] == p
}

# ---- decision ----
allow { required_perms == [] }
allow {
  some p
  required_perms[_] == p
  has_perm(p)
}

# Optional debug
decision = {
  "email": input.email,
  "sub": input.sub,
  "app": input.app,
  "method": norm_method(input.action),
  "path": norm_path(input.object),
  "required_perms": required_perms,
  "effective_roles": effective_roles,
  "allowed": allow
}

