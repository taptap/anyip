package main

import (
	"net"
	"testing"
)

func TestExtractIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"127-0-0-1", "127.0.0.1"},
		{"192-168-1-50", "192.168.1.50"},
		{"10-0-0-1", "10.0.0.1"},
		{"app.192-168-1-50", "192.168.1.50"},
		{"api.staging.172-16-0-1", "172.16.0.1"},
		{"deep.nested.sub.10-0-0-1", "10.0.0.1"},
		{"0-0-0-0", "0.0.0.0"},
		{"255-255-255-255", "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := extractIP(tt.input)
			if ip == nil {
				t.Fatalf("extractIP(%q) = nil, want %s", tt.input, tt.want)
			}
			if ip.String() != tt.want {
				t.Errorf("extractIP(%q) = %s, want %s", tt.input, ip.String(), tt.want)
			}
		})
	}
}

func TestExtractIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2001-db8--1", "2001:db8::1"},
		{"fe80--1", "fe80::1"},
		{"--1", "::1"},
		{"2001-db8-0-0-0-0-0-1", "2001:db8::1"},
		{"app.2001-db8--1", "2001:db8::1"},
		{"app.fe80--abcd", "fe80::abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := extractIP(tt.input)
			if ip == nil {
				t.Fatalf("extractIP(%q) = nil, want %s", tt.input, tt.want)
			}
			// Normalize both for comparison
			want := net.ParseIP(tt.want)
			if !ip.Equal(want) {
				t.Errorf("extractIP(%q) = %s, want %s", tt.input, ip.String(), want.String())
			}
		})
	}
}

func TestExtractIPInvalid(t *testing.T) {
	tests := []string{
		"",
		"hello",
		"not-an-ip",
		"999-999-999-999",
		"just-three-1",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			ip := extractIP(tt)
			if ip != nil {
				t.Errorf("extractIP(%q) = %s, want nil", tt, ip.String())
			}
		})
	}
}

func BenchmarkExtractIPv4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractIP("app.staging.192-168-1-50")
	}
}

func BenchmarkExtractIPv6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractIP("app.2001-db8--1")
	}
}
