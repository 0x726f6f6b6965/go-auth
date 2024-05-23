package mask

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func GetValueByMask(request interface{}, mask *fieldmaskpb.FieldMask, naming func(string) string) (map[string]interface{}, error) {
	rv := reflect.ValueOf(request)
	if rv.Kind() == reflect.Ptr && !rv.IsNil() {
		rv = rv.Elem()
	}
	result := make(map[string]interface{})
	for _, path := range mask.GetPaths() {
		crv := rv
		for _, fieldName := range strings.Split(path, ".") {
			if fieldName == "" {
				return nil, errors.Join(ErrFieldName, fmt.Errorf("path: \"%s\"", path))
			}
			newName := naming(fieldName)
			val := crv.FieldByName(newName)
			if val.IsValid() {
				if val.Kind() == reflect.Ptr && !val.IsNil() {
					val = val.Elem()
				}
				crv = val
			} else {
				return nil, errors.Join(ErrFildValue, fmt.Errorf("path: \"%s\"", path))
			}
		}
		result[path] = crv.Interface()
	}
	return result, nil
}
