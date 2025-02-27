package helpers

import (
	"strings"
)

// formatMessageCode converts a message to kebab-case (lowercase with dashes)
func FormatMessageCode(message string) string {
	return strings.ToLower(strings.ReplaceAll(message, " ", "-"))
}
