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

// parseExactIPLabel parses a label that must be exactly an IP address (no prefix allowed).
// "192-168-1-50" → 192.168.1.50 ✓   "myapp-192-168-1-50" → nil ✗
func parseExactIPLabel(label string) net.IP {
	// Try IPv6 first (same reason as extractIP)
	if ip := tryIPv6(label); ip != nil {
		return ip
	}
	// IPv4: must be exactly 4 dash-separated parts
	parts := strings.Split(label, "-")
	if len(parts) != 4 {
		return nil
	}
	ipStr := strings.Join(parts, ".")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// CertSubsPolicy controls which IP labels are allowed for subdomain cert requests.
// Entries can be exact labels (e.g., "127-0-0-1"), CIDRs (e.g., "10.0.0.0/8"),
// or keywords: "private" (all private/reserved IPs) or "all" (any IP).
// An empty policy means subdomain certs are disabled entirely.
type CertSubsPolicy struct {
	labels          map[string]bool
	cidrs           []*net.IPNet
	allowAllPrivate bool // true when "private" keyword is used
	allowAll        bool // true when "all" keyword is used
}

// NewCertSubsPolicy creates a policy from a list of entries.
// Each entry is an exact label (e.g., "127-0-0-1"), a CIDR (e.g., "10.0.0.0/8"),
// or a keyword: "private" (all private/reserved IPs) or "all" (any IP).
// An empty/nil list disables subdomain certs entirely.
func NewCertSubsPolicy(entries []string) CertSubsPolicy {
	p := CertSubsPolicy{
		labels: make(map[string]bool),
	}
	for _, entry := range entries {
		if entry == "all" {
			p.allowAll = true
		} else if entry == "private" {
			p.allowAllPrivate = true
		} else if _, cidr, err := net.ParseCIDR(entry); err == nil {
			p.cidrs = append(p.cidrs, cidr)
		} else {
			p.labels[entry] = true
		}
	}
	return p
}

// IsAllowed checks if a label is allowed by this policy.
func (p CertSubsPolicy) IsAllowed(label string) bool {
	// Exact label match
	if p.labels[label] {
		return true
	}
	// Parse the label to an IP for CIDR/private/all checks
	ip := parseExactIPLabel(label)
	if ip == nil {
		return false
	}
	if p.allowAll {
		return true
	}
	// Check CIDRs
	for _, cidr := range p.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if p.allowAllPrivate {
		return isPrivateIP(ip)
	}
	return false
}

// IsEnabled returns true if the policy allows any certificates at all.
func (p CertSubsPolicy) IsEnabled() bool {
	return p.allowAll || p.allowAllPrivate || len(p.labels) > 0 || len(p.cidrs) > 0
}

// Description returns a human-readable description of the policy for display.
func (p CertSubsPolicy) Description() string {
	if p.allowAll {
		return "any IP"
	}
	if p.allowAllPrivate {
		return "any private/reserved IP"
	}
	var parts []string
	for l := range p.labels {
		parts = append(parts, l)
	}
	for _, c := range p.cidrs {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, ", ")
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
