package app.rbac

import future.keywords.in
import future.keywords.if

default allow := false

#####################
# Helpers
#####################

norm_method(m) := upper(m)

# Normalize path
norm_path("/") := "/"
norm_path(p) := trim_suffix(p, "/") if { p != "/"; endswith(p, "/") }
norm_path(p) := p if { p != "/"; not endswith(p, "/") }

# Convert express-like paths to regex
path_to_regex(path) := re if {
  tmp1 := regex.replace(`:([A-Za-z0-9_]+)\*`, path, `.*`)
  tmp2 := regex.replace(`:([A-Za-z0-9_]+)`,     tmp1, `[^/]+`)
  re   := sprintf("^%s/?$", [tmp2])
}

#################################
# Route matching
#################################

# Is there a PUBLIC route that matches this request?
public_match := true if {
  svc := input.app
  # Find the rules for the "jinbe" app
  some rm in data.route_map[svc].rules
  
  # Check if the method matches (e.g., "GET" == "GET")
  rm.method == norm_method(input.action)
  
  # Check if the path matches (e.g., "/docs" matches regex "^/docs/?$")
  regex.match(path_to_regex(rm.path), norm_path(input.object))
  
  # Check if it's public
  rm.permission == null
}

#############
# Decisions
#############

# 1) Allow if it's a public route
allow if public_match


###############################################################
# DEBUGGING RULESET
#
# To debug, run the command in the chat.
#
###############################################################

# --- Step 1: Check input variables ---
debug_input := {
    "app": input.app,
    "norm_method": norm_method(input.action),
    "norm_path": norm_path(input.object),
}

# Helper to check if a single rule matches the input (REMOVED - logic moved inline)
# is_matching_rule(rm) if {
#     rm.method == norm_method(input.action)
#     regex.match(path_to_regex(rm.path), norm_path(input.object))
# }

# --- Step 2: Check matching routes ---
# Find all rules that match the app, method, and path
matching_rules := [rm |
    rm in data.route_map[input.app].rules
    # Logic from is_matching_rule moved back inline
    rm.method == norm_method(input.action)
    regex.match(path_to_regex(rm.path), norm_path(input.object))
]

# --- Step 3: Check if any matching rule is public ---
is_public_match if {
    count(matching_rules) > 0
    some r in matching_rules
    r.permission == null
}

# --- Final Debug Output ---
debug_output := {
    "__NOTE__": "Query this variable (debug_output) to see trace",
    "0_input": debug_input,
    "1_matching_rules_found": matching_rules,
    "2_is_public_match_variable": is_public_match,
    "3_public_match_variable": public_match,
    "FINAL_DECISION_allow": allow
}



