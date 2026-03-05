package main

import (
	"path/filepath"
	"strings"
	"testing"
)

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

func TestSubCertDir_Valid(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	dir, err := subCertDir("127-0-0-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join("/tmp/certs", "sub", "127-0-0-1")
	if dir != want {
		t.Errorf("dir = %s, want %s", dir, want)
	}
}

func TestSubCertDir_PathTraversal(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	cases := []string{
		"../../../etc",
		"../../passwd",
		"..",
		"foo/../../etc",
	}
	for _, label := range cases {
		_, err := subCertDir(label)
		if err == nil {
			t.Errorf("subCertDir(%q) should have returned error", label)
		}
		if err != nil && !strings.Contains(err.Error(), "path escapes") {
			t.Errorf("subCertDir(%q) error = %v, want 'path escapes'", label, err)
		}
	}
}

func TestSubdomainEcdsaCertFiles_Valid(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	cs := NewChallengeStore()
	m := NewCertManager(cs)

	cert, key := m.SubdomainEcdsaCertFiles("127-0-0-1")
	if cert == "" || key == "" {
		t.Error("expected non-empty cert and key paths")
	}
	if !strings.Contains(cert, "fullchain.pem") {
		t.Errorf("cert = %s, want fullchain.pem", cert)
	}
}

func TestSubdomainEcdsaCertFiles_InvalidLabel(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	cs := NewChallengeStore()
	m := NewCertManager(cs)

	cert, key := m.SubdomainEcdsaCertFiles("../../etc")
	if cert != "" || key != "" {
		t.Errorf("expected empty paths for traversal label, got cert=%s key=%s", cert, key)
	}
}

func TestSubdomainRsaCertFiles_Valid(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	cs := NewChallengeStore()
	m := NewCertManager(cs)

	cert, key := m.SubdomainRsaCertFiles("127-0-0-1")
	if cert == "" || key == "" {
		t.Error("expected non-empty cert and key paths")
	}
	if !strings.Contains(cert, "fullchain-rsa.pem") {
		t.Errorf("cert = %s, want fullchain-rsa.pem", cert)
	}
}

func TestSubdomainRsaCertFiles_InvalidLabel(t *testing.T) {
	cfg = Config{CertDir: "/tmp/certs"}
	cs := NewChallengeStore()
	m := NewCertManager(cs)

	cert, key := m.SubdomainRsaCertFiles("../../etc")
	if cert != "" || key != "" {
		t.Errorf("expected empty paths for traversal label, got cert=%s key=%s", cert, key)
	}
}
