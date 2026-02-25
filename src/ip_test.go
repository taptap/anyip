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
		{"0-0-0-0", "0.0.0.0"},
		{"255-255-255-255", "255.255.255.255"},
		// With prefix labels
		{"myapp-192-168-1-50", "192.168.1.50"},
		{"api-10-0-0-1", "10.0.0.1"},
		{"my-cool-app-172-16-0-1", "172.16.0.1"},
		// Dot-separated (multi-level, last label used)
		{"app.192-168-1-50", "192.168.1.50"},
		{"api.staging.172-16-0-1", "172.16.0.1"},
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
		// With dots (last label)
		{"app.2001-db8--1", "2001:db8::1"},
		{"app.fe80--abcd", "fe80::abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := extractIP(tt.input)
			if ip == nil {
				t.Fatalf("extractIP(%q) = nil, want %s", tt.input, tt.want)
			}
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
		"only-two-1",
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

func TestIsPrivateIP(t *testing.T) {
	private := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1", "fe80::1", "fc00::1"}
	public := []string{"8.8.8.8", "1.1.1.1", "203.0.113.1", "2001:db8::1"}

	for _, s := range private {
		ip := net.ParseIP(s)
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = false, want true", s)
		}
	}
	for _, s := range public {
		ip := net.ParseIP(s)
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = true, want false", s)
		}
	}
}

func BenchmarkExtractIPv4Simple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractIP("127-0-0-1")
	}
}

func BenchmarkExtractIPv4WithPrefix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractIP("myapp-192-168-1-50")
	}
}

func BenchmarkExtractIPv6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractIP("2001-db8--1")
	}
}
