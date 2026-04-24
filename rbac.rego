package rbac

import future.keywords.every

default allow = false

# ─── APP-SCOPED ROLE / PERMISSION HELPERS ───
# Complete-rule functions returning sets — avoids parametric partial set
# rule syntax issues across OPA versions.

roles_for(app) = roles {
  roles := {role |
    group := data.bindings.group_membership[input.email][_]
    role := data.bindings.groups[group]["global"][_]
  } | {role |
    group := data.bindings.group_membership[input.email][_]
    role := data.bindings.groups[group][app][_]
  } | {role |
    role := data.bindings.emails[input.email]["global"][_]
  } | {role |
    role := data.bindings.emails[input.email][app][_]
  }
}

perms_for(app) = perms {
  perms := {perm |
    role := roles_for(app)[_]
    perm := data.roles.global[role][_]
  } | {perm |
    role := roles_for(app)[_]
    perm := data.roles[app][role][_]
  }
}

# ─── PATH MATCHING ───

path_matches(pattern, request_path) {
  pattern == request_path
}

path_matches(pattern, request_path) {
  contains(pattern, ":any*")
  prefix_pattern := trim_suffix(pattern, ":any*")
  prefix_parts := split(trim_suffix(prefix_pattern, "/"), "/")
  path_parts := split(request_path, "/")
  count(path_parts) >= count(prefix_parts)
  every i, _ in prefix_parts {
    part_matches(prefix_parts[i], path_parts[i])
  }
}

path_matches(pattern, request_path) {
  contains(pattern, ":")
  not contains(pattern, ":any*")
  pattern_parts := split(pattern, "/")
  path_parts := split(request_path, "/")
  count(pattern_parts) == count(path_parts)
  every i, _ in pattern_parts {
    part_matches(pattern_parts[i], path_parts[i])
  }
}

part_matches(pattern_part, _) {
  startswith(pattern_part, ":")
}

part_matches(pattern_part, path_part) {
  not startswith(pattern_part, ":")
  pattern_part == path_part
}

# ─── ALLOW RULES ───

# Wildcard (super_admin): has "*" permission in any service context
# Constrain app iteration to services with defined roles.
allow {
  some app
  data.roles[app]
  perms_for(app)["*"]
}

# Public route: no permission required
# NOTE: route_map entries MUST NOT use catch-all wildcards that overlap
# with protected routes from other services (keep route_maps disjoint).
allow {
  some app
  rule := data.route_map[app].rules[_]
  rule.method == input.action
  path_matches(rule.path, input.object)
  not rule.permission
}

# Protected route: user must hold the required permission for this service
allow {
  some app
  rule := data.route_map[app].rules[_]
  rule.method == input.action
  path_matches(rule.path, input.object)
  rule.permission
  perms_for(app)[rule.permission]
}

# ─── USER INFO (requires input.app — for simulator / direct OPA queries) ───

user_info = info {
  data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "app": input.app,
    "groups": data.bindings.group_membership[input.email],
    "roles": roles_for(input.app),
    "permissions": perms_for(input.app),
  }
}

user_info = info {
  not data.bindings.group_membership[input.email]
  not data.bindings.emails[input.email]
  info := {
    "email": input.email,
    "app": input.app,
    "groups": [],
    "roles": set(),
    "permissions": set(),
  }
}

# ─── ALL-APPS USER INFO ───

user_roles_all_apps[app] = roles {
  some app
  data.roles[app]
  roles := {role |
    group := data.bindings.group_membership[input.email][_]
    role := data.bindings.groups[group][app][_]
  }
}

user_info_all = info {
  data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "groups": data.bindings.group_membership[input.email],
    "roles_by_app": user_roles_all_apps,
  }
}

user_info_all = info {
  not data.bindings.group_membership[input.email]
  info := {
    "email": input.email,
    "groups": [],
    "roles_by_app": {},
  }
}
