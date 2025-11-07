package opal

default allow := false

user_roles contains role if {
	roles := data.bindings.emails[input.email]
	role := roles[_]
}

user_roles contains role if {
	email := input.email
	groups := data.bindings.group_membership[email]
	group := groups[_]
	some role in data.bindings.groups[group]
}

is_admin if {
	"admin" in user_roles
}

matching_rule contains rule if {
	project := input.app
	route_config := data.route_map[project]
	some rule in route_config.rules
	rule.method == input.action
	path_matches(rule.path, input.object)
}

path_matches(pattern, request_path) if {
	pattern == request_path
}

path_matches(pattern, request_path) if {
	contains(pattern, ":any*")
	prefix := trim_suffix(pattern, ":any*")
	startswith(request_path, prefix)
}

allow if {
	is_admin
}

allow if {
	some rule in matching_rule
	rule.permission == null
}

allow if {
	some rule in matching_rule
	rule.permission != null
	user_has_permission(rule.permission)
}

user_has_permission(_) if {
	some role in user_roles
	perms := data.roles[role]
	perm := perms[_]
	perm == "*"
}

user_has_permission(permission) if {
	some role in user_roles
	perms := data.roles[role]
	perm := perms[_]
	permission == perm
}
