package opal
import future.keywords.in

default allow := false

user_roles contains role if {
	# From direct email bindings
	roles := data.bindings.emails[input.email]
	role := roles[_]
}

user_roles contains role if {
	# From group memberships
	email := input.email
	groups := data.bindings.group_membership[email]
	group := groups[_]
	some role in data.bindings.groups[group]
}

# Admin role has wildcard access
is_admin if {
	"admin" in user_roles
}

# Set of matching route rules
matching_rule contains rule if {
	project := input.app
	route_config := data.route_map[project]
	some rule in route_config.rules
	rule.method == input.action
	path_matches(rule.path, input.object)
}

# Path matching (exact)rule
path_matches(pattern, request_path) if {
	pattern == request_path
}

# Path matching (:any* suffix wildcard)
path_matches(pattern, request_path) if {
	contains(pattern, ":any*")
	prefix := trim_suffix(pattern, ":any*")
	startswith(request_path, prefix)
}

# Main authorization logic

# Admin can do everything
allow if {
	is_admin
}

# Route requires no permission
allow if {
	some rule in matching_rule
	rule.permission == null
}

# Route requires a permission; user must have it
allow if {
	some rule in matching_rule
	rule.permission != null
	user_has_permission(rule.permission)
}

# Permission checks
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

