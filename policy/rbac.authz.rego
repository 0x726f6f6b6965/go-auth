package rbac.authz

import rego.v1

default allow := false

allow if user_is_admin

allow if {
	some grant in user_is_granted
	input.action == grant.action
	input.resource == grant.resource
}

user_is_admin if {
	"admin" in data.user_roles[input.role]
}

user_is_granted contains grant if {
	some role in data.user_roles[input.role]

	some grant in data.role_grants[role]
}
