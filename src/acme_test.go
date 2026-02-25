package main

import "testing"

func TestChallengeStore_SetGet(t *testing.T) {
	cs := NewChallengeStore()
	cs.Set("", "root-token")

	if got := cs.Get(""); got != "root-token" {
		t.Errorf("Get(\"\") = %s, want root-token", got)
	}
}

func TestChallengeStore_GetMissing(t *testing.T) {
	cs := NewChallengeStore()

	if got := cs.Get("nonexistent"); got != "" {
		t.Errorf("Get(nonexistent) = %s, want empty", got)
	}
}

func TestChallengeStore_Clear(t *testing.T) {
	cs := NewChallengeStore()
	cs.Set("label", "token-123")
	cs.Clear("label")

	if got := cs.Get("label"); got != "" {
		t.Errorf("Get after Clear = %s, want empty", got)
	}
}

func TestChallengeStore_MultipleLabels(t *testing.T) {
	cs := NewChallengeStore()
	cs.Set("", "root-token")
	cs.Set("127-0-0-1", "sub-token")

	if got := cs.Get(""); got != "root-token" {
		t.Errorf("Get(\"\") = %s, want root-token", got)
	}
	if got := cs.Get("127-0-0-1"); got != "sub-token" {
		t.Errorf("Get(127-0-0-1) = %s, want sub-token", got)
	}
}
