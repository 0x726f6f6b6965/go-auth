package rbac.authz_test

import rego.v1
import data.rbac.authz as policy

user_roles := {"admin": ["admin"], "user": ["user"]}

role_grants := {
	"user": [
		{"action": "read", "resource": "user"},
		{"action": "edit", "resource": "*"},
	],
	"refresh": [{"action": "edit", "resource": "token-update"}],
}

test_allow_if_admin if {
	policy.allow with input as {"role": "admin", "action": "read", "resource": "user"}
		with data.user_roles as user_roles
		with data.role_grants as role_grants
}

test_allow_if_user_read_user if {
	policy.allow with input as {"role": "user", "action": "read", "resource": "user"}
		with data.user_roles as user_roles
		with data.role_grants as role_grants
}

test_allow_if_user_read_token_update if {
	not policy.allow with input as {"role": "user", "action": "read", "resource": "token-update"}
		with data.user_roles as user_roles
		with data.role_grants as role_grants
}
