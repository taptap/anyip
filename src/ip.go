package main

import (
	"net"
	"strings"
)

// extractIP scans a subdomain string to find an embedded IP address.
// The subdomain is a single DNS label (no dots — everything before the base domain).
//
// IPv4: rightmost 4 dash-separated decimal octets.
//
//	"myapp-192-168-1-50" → 192.168.1.50
//	"127-0-0-1"          → 127.0.0.1
//
// IPv6: dashes become colons, double-dash becomes ::
//
//	"2001-db8--1"   → 2001:db8::1
//	"fe80--1"       → fe80::1
//	"---1"          → ::1
func extractIP(subdomain string) net.IP {
	if subdomain == "" {
		return nil
	}

	// Single-label: no dots expected (wildcard cert = one level)
	// But be tolerant if dots sneak in — take the last label
	if idx := strings.LastIndex(subdomain, "."); idx >= 0 {
		subdomain = subdomain[idx+1:]
	}

	// Try IPv6 first — a full IPv6 like "2001-db8-0-0-0-0-0-1" has 8 parts
	// and the rightmost 4 would falsely match as IPv4. IPv6 parser is stricter
	// (requires valid hex groups), so trying it first is safe.
	if ip := tryIPv6(subdomain); ip != nil {
		return ip
	}

	// Then try IPv4
	if ip := tryIPv4(subdomain); ip != nil {
		return ip
	}

	return nil
}

// tryIPv4 extracts the rightmost 4 dash-separated octets as an IPv4 address.
// "myapp-192-168-1-50" → take last 4 parts → "192.168.1.50"
func tryIPv4(s string) net.IP {
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		return nil
	}

	// Take the rightmost 4 parts
	ipParts := parts[len(parts)-4:]
	ipStr := strings.Join(ipParts, ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// tryIPv6 converts dashes to colons, double-dash to ::
// "2001-db8--1" → "2001:db8::1"
func tryIPv6(s string) net.IP {
	if !strings.Contains(s, "-") {
		return nil
	}

	// Double-dash → ::
	ipStr := strings.ReplaceAll(s, "--", "::")
	// Remaining single dashes → :
	ipStr = strings.ReplaceAll(ipStr, "-", ":")

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		return nil
	}
	return ip
}
