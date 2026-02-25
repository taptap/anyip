package main

import (
	"os"
	"testing"
)

func TestEnvOr(t *testing.T) {
	key := "ANYIP_TEST_ENVVAR_" + t.Name()

	// Fallback when not set
	if got := envOr(key, "default"); got != "default" {
		t.Errorf("envOr(%s) = %s, want default", key, got)
	}

	// Returns env value when set
	os.Setenv(key, "custom")
	defer os.Unsetenv(key)
	if got := envOr(key, "default"); got != "custom" {
		t.Errorf("envOr(%s) = %s, want custom", key, got)
	}
}

func TestEnvOrUint(t *testing.T) {
	key := "ANYIP_TEST_ENVVAR_" + t.Name()

	// Fallback when not set
	if got := envOrUint(key, 42); got != 42 {
		t.Errorf("envOrUint(%s) = %d, want 42", key, got)
	}

	// Returns parsed value
	os.Setenv(key, "100")
	defer os.Unsetenv(key)
	if got := envOrUint(key, 42); got != 100 {
		t.Errorf("envOrUint(%s) = %d, want 100", key, got)
	}

	// Fallback on invalid value
	os.Setenv(key, "notanumber")
	if got := envOrUint(key, 42); got != 42 {
		t.Errorf("envOrUint(%s, invalid) = %d, want 42", key, got)
	}
}
