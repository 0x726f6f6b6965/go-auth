# go-auth

## About it
This is the repository for authentication and authorization services. The authorization service used OPA(open policy agent) to implement.

## Authorization
The authorized feature is implemented through OPA(open policy agent) based on tokens. The rules on the repository are in this file(`/policy/rbac.authz.rego`) and the data is in the file(`/policy/basic.json`). More information about rego is [here](https://www.openpolicyagent.org/).
