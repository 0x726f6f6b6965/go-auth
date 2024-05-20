package helper

import (
	"regexp"
	"strings"
)

func Empty(s string) bool {
	return strings.Trim(s, " ") == ""
}

// ValidEmailFormat email verify
func ValidEmailFormat(email string) bool {
	pattern := `^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$`
	//pattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`

	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}
