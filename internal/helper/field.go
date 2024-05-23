package helper

import (
	"reflect"
	"strings"
)

func GetNameByTag(fieldName, targetTag string, val interface{}) string {
	rv := reflect.ValueOf(val)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	rs, ok := rv.Type().FieldByName(fieldName)
	if !ok {
		return ""
	}
	tagName := rs.Tag.Get(targetTag)
	switch targetTag {
	case "gorm":
		for _, ele := range strings.Split(tagName, ";") {
			if strings.HasPrefix(ele, "column:") {
				return strings.Trim(strings.TrimPrefix(ele, "column:"), " ")
			}
		}
	}
	return tagName
}
