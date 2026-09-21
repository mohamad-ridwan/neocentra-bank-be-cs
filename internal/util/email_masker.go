package util

import (
	"strings"
)

// MaskEmail masks an email string, e.g.:
// "user@example.com" -> "u***r@example.com"
// "budi.santoso@neocentra.bank" -> "b***o@neocentra.bank"
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	user := parts[0]
	domain := parts[1]

	if len(user) <= 1 {
		return user + "***@" + domain
	} else if len(user) == 2 {
		return string(user[0]) + "***@" + domain
	}

	firstChar := string(user[0])
	lastChar := string(user[len(user)-1])
	return firstChar + "***" + lastChar + "@" + domain
}
