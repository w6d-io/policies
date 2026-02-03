package rbac

import future.keywords.every

default allow = false

# --- 1. USER ROLE AGGREGATION (per service) ---

user_roles_for_app[role] {                                                                                                                                                                
  groups := data.bindings.group_membership[input.email]                                                                                                                                 
  group := groups[_]                                                                                                                                                                    
  group_roles := data.groups.groups[group]                                                                                                                                              
  global_roles := group_roles["global"]                                                                                                                                                 
  role := global_roles[_]                                                                                                                                                               
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_roles_for_app[role] {                                                                                                                                                                
  groups := data.bindings.group_membership[input.email]                                                                                                                                 
  group := groups[_]                                                                                                                                                                    
  group_roles := data.groups.groups[group]                                                                                                                                              
  service_roles := group_roles[input.app]                                                                                                                                               
  role := service_roles[_]                                                                                                                                                              
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_roles_for_app[role] {                                                                                                                                                                
  email_roles := data.bindings.emails[input.email]                                                                                                                                      
  global_roles := email_roles["global"]                                                                                                                                                 
  role := global_roles[_]                                                                                                                                                               
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_roles_for_app[role] {                                                                                                                                                                
  email_roles := data.bindings.emails[input.email]                                                                                                                                      
  service_roles := email_roles[input.app]                                                                                                                                               
  role := service_roles[_]                                                                                                                                                              
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 2. ROLE DEFINITIONS LOOKUP (handles array format) ---                                                                                                                               
                                                                                                                                                                                        
role_permissions[role_name] = perms {                                                                                                                                                     
  role_def := data.roles[input.app].roles[_]                                                                                                                                            
  role_name := role_def.name                                                                                                                                                            
  perms := role_def.permissions                                                                                                                                                         
}                                                                                                                                                                                         
                                                                                                                                                                                        
role_inherits[role_name] = inherited {                                                                                                                                                    
  role_def := data.roles[input.app].roles[_]                                                                                                                                            
  role_name := role_def.name                                                                                                                                                            
  role_def.inherits                                                                                                                                                                     
  inherited := role_def.inherits                                                                                                                                                        
}                                                                                                                                                                                         
                                                                                                                                                                                        
role_inherits[role_name] = [] {                                                                                                                                                           
  role_def := data.roles[input.app].roles[_]                                                                                                                                            
  role_name := role_def.name                                                                                                                                                            
  not role_def.inherits                                                                                                                                                                 
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 3. USER PERMISSION AGGREGATION ---                                                                                                                                                  
                                                                                                                                                                                        
user_permissions[perm] {                                                                                                                                                                  
  role := user_roles_for_app[_]                                                                                                                                                         
  perms := role_permissions[role]                                                                                                                                                       
  perm := perms[_]                                                                                                                                                                      
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_permissions[perm] {                                                                                                                                                                  
  role := user_roles_for_app[_]                                                                                                                                                         
  inherited_roles := role_inherits[role]                                                                                                                                                
  inherited_role := inherited_roles[_]                                                                                                                                                  
  perms := role_permissions[inherited_role]                                                                                                                                             
  perm := perms[_]                                                                                                                                                                      
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_permissions[perm] {                                                                                                                                                                  
  role := user_roles_for_app[_]                                                                                                                                                         
  inherited_roles := role_inherits[role]                                                                                                                                                
  inherited_role := inherited_roles[_]                                                                                                                                                  
  deep_inherited := role_inherits[inherited_role]                                                                                                                                       
  deep_role := deep_inherited[_]                                                                                                                                                        
  perms := role_permissions[deep_role]                                                                                                                                                  
  perm := perms[_]                                                                                                                                                                      
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 4. REQUEST ROUTE MATCHING ---                                                                                                                                                       
                                                                                                                                                                                        
matching_rules[rule] {                                                                                                                                                                    
  route_config := data.route_map[input.app]                                                                                                                                             
  rule := route_config.routes[_]                                                                                                                                                        
  rule.method == input.action                                                                                                                                                           
  path_matches(rule.path, input.object)                                                                                                                                                 
}                                                                                                                                                                                         
                                                                                                                                                                                        
path_matches(pattern, request_path) {                                                                                                                                                     
  pattern == request_path                                                                                                                                                               
}                                                                                                                                                                                         
                                                                                                                                                                                        
path_matches(pattern, request_path) {                                                                                                                                                     
  contains(pattern, ":any*")                                                                                                                                                            
  prefix := trim_suffix(pattern, ":any*")                                                                                                                                               
  startswith(request_path, prefix)                                                                                                                                                      
}                                                                                                                                                                                         
                                                                                                                                                                                        
path_matches(pattern, request_path) {                                                                                                                                                     
  contains(pattern, ":")                                                                                                                                                                
  not contains(pattern, ":any*")                                                                                                                                                        
  pattern_parts := split(pattern, "/")                                                                                                                                                  
  path_parts := split(request_path, "/")                                                                                                                                                
  count(pattern_parts) == count(path_parts)                                                                                                                                             
  all_parts_match(pattern_parts, path_parts)                                                                                                                                            
}                                                                                                                                                                                         
                                                                                                                                                                                        
all_parts_match(pattern_parts, path_parts) {                                                                                                                                              
  count(pattern_parts) == count(path_parts)                                                                                                                                             
  every i, _ in pattern_parts {                                                                                                                                                         
      part_matches(pattern_parts[i], path_parts[i])                                                                                                                                     
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
part_matches(pattern_part, path_part) {                                                                                                                                                   
  startswith(pattern_part, ":")                                                                                                                                                         
}                                                                                                                                                                                         
                                                                                                                                                                                        
part_matches(pattern_part, path_part) {                                                                                                                                                   
  not startswith(pattern_part, ":")                                                                                                                                                     
  pattern_part == path_part                                                                                                                                                             
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 5. PERMISSION CHECK HELPERS ---                                                                                                                                                     
                                                                                                                                                                                        
user_has_permission(permission) {                                                                                                                                                         
  user_permissions[permission]                                                                                                                                                          
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_has_permission(_) {                                                                                                                                                                  
  user_permissions["*"]                                                                                                                                                                 
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_has_all_permissions(required_perms) {                                                                                                                                                
  every perm in required_perms {                                                                                                                                                        
      user_has_permission(perm)                                                                                                                                                         
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 6. USER INFO ENDPOINT ---                                                                                                                                                           
                                                                                                                                                                                        
user_info = info {                                                                                                                                                                        
  data.bindings.group_membership[input.email]                                                                                                                                           
  info := {                                                                                                                                                                             
      "email": input.email,                                                                                                                                                             
      "app": input.app,                                                                                                                                                                 
      "groups": data.bindings.group_membership[input.email],                                                                                                                            
      "roles": user_roles_for_app,                                                                                                                                                      
      "permissions": user_permissions                                                                                                                                                   
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
      "permissions": set()                                                                                                                                                              
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 7. ALL APPS USER INFO ---                                                                                                                                                           
                                                                                                                                                                                        
user_roles_all_apps[app] = roles {                                                                                                                                                        
  some app                                                                                                                                                                              
  data.roles[app]                                                                                                                                                                       
  roles := {role |                                                                                                                                                                      
      groups := data.bindings.group_membership[input.email]                                                                                                                             
      group := groups[_]                                                                                                                                                                
      group_roles := data.groups.groups[group]                                                                                                                                          
      app_roles := group_roles[app]                                                                                                                                                     
      role := app_roles[_]                                                                                                                                                              
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_info_all = info {                                                                                                                                                                    
  data.bindings.group_membership[input.email]                                                                                                                                           
  info := {                                                                                                                                                                             
      "email": input.email,                                                                                                                                                             
      "groups": data.bindings.group_membership[input.email],                                                                                                                            
      "roles_by_app": user_roles_all_apps                                                                                                                                               
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
user_info_all = info {                                                                                                                                                                    
  not data.bindings.group_membership[input.email]                                                                                                                                       
  info := {                                                                                                                                                                             
      "email": input.email,                                                                                                                                                             
      "groups": [],                                                                                                                                                                     
      "roles_by_app": {}                                                                                                                                                                
  }                                                                                                                                                                                     
}                                                                                                                                                                                         
                                                                                                                                                                                        
# --- 8. ALLOW LOGIC ---                                                                                                                                                                  
                                                                                                                                                                                        
allow {                                                                                                                                                                                   
  rule := matching_rules[_]                                                                                                                                                             
  rule.public == true                                                                                                                                                                   
}                                                                                                                                                                                         
                                                                                                                                                                                        
allow {                                                                                                                                                                                   
  rule := matching_rules[_]                                                                                                                                                             
  rule.public != true                                                                                                                                                                   
  count(rule.requiredPermissions) > 0                                                                                                                                                   
  user_has_all_permissions(rule.requiredPermissions)                                                                                                                                    
}                                                                                                                                                                                         
                                                                                                                                                                                        
allow {                                                                                                                                                                                   
  rule := matching_rules[_]                                                                                                                                                             
  rule.public != true                                                                                                                                                                   
  count(rule.requiredPermissions) == 0                                                                                                                                                  
}  
