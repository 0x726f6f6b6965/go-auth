package policy

import (
	_ "embed"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

//go:embed rbac.authz.rego
var rbac []byte

//go:embed basic.json
var data []byte

func GetRbac() []byte {
	return rbac
}

func GetStorage() (storage.Store, error) {
	result := make(map[string]interface{})
	err := util.UnmarshalJSON([]byte(data), &result)
	if err != nil {
		return nil, err
	}
	store := inmem.NewFromObject(result)
	return store, nil
}

func GetData() (map[string]interface{}, error) {
	result := make(map[string]interface{})
	err := util.UnmarshalJSON([]byte(data), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
