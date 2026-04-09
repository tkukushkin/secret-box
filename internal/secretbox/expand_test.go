package secretbox

import (
	"reflect"
	"testing"
)

func TestExpand_SingleVar(t *testing.T) {
	result := ExpandVariables(
		[]string{"--password=$(DB_PASS)"},
		map[string]string{"DB_PASS": "secret123"},
	)
	expected := []string{"--password=secret123"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_MultipleVarsInArg(t *testing.T) {
	result := ExpandVariables(
		[]string{"$(USER):$(PASS)"},
		map[string]string{"USER": "admin", "PASS": "s3cret"},
	)
	expected := []string{"admin:s3cret"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_MultipleArgs(t *testing.T) {
	result := ExpandVariables(
		[]string{"--user=$(USER)", "--pass=$(PASS)"},
		map[string]string{"USER": "admin", "PASS": "s3cret"},
	)
	expected := []string{"--user=admin", "--pass=s3cret"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_UnmatchedVar(t *testing.T) {
	result := ExpandVariables(
		[]string{"$(UNKNOWN)"},
		map[string]string{"KNOWN": "value"},
	)
	expected := []string{"$(UNKNOWN)"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_NoVariables(t *testing.T) {
	result := ExpandVariables(
		[]string{"echo", "hello"},
		map[string]string{"VAR": "value"},
	)
	expected := []string{"echo", "hello"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_EmptyValues(t *testing.T) {
	result := ExpandVariables(
		[]string{"$(VAR)"},
		map[string]string{},
	)
	expected := []string{"$(VAR)"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

func TestExpand_EmptyArgs(t *testing.T) {
	result := ExpandVariables(
		[]string{},
		map[string]string{"VAR": "value"},
	)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestExpand_SpecialChars(t *testing.T) {
	result := ExpandVariables(
		[]string{"$(PASS)"},
		map[string]string{"PASS": "p@ss w0rd!\"'$"},
	)
	expected := []string{"p@ss w0rd!\"'$"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}
