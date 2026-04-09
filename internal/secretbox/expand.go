package secretbox

import "strings"

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
