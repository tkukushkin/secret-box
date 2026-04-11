package secretbox

import (
	"regexp"
	"strings"
)

var secretRefPattern = regexp.MustCompile(`\$\(([^)]+)\)`)

// FindSecretRefs extracts unique secret names referenced via $(name) in the given strings.
func FindSecretRefs(strs []string) []string {
	seen := make(map[string]bool)
	var refs []string
	for _, s := range strs {
		for _, match := range secretRefPattern.FindAllStringSubmatch(s, -1) {
			name := match[1]
			if !seen[name] {
				seen[name] = true
				refs = append(refs, name)
			}
		}
	}
	return refs
}

// ExpandVariables replaces $(name) references in arguments with corresponding values.
func ExpandVariables(arguments []string, values map[string]string) []string {
	result := make([]string, len(arguments))
	for i, arg := range arguments {
		expanded := arg
		for varName, value := range values {
			expanded = strings.ReplaceAll(expanded, "$("+varName+")", value)
		}
		result[i] = expanded
	}
	return result
}
