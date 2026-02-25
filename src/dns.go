package main

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNSHandler handles all DNS queries.
type DNSHandler struct {
	challenges *ChallengeStore
}

func NewDNSHandler(challenges *ChallengeStore) *DNSHandler {
	return &DNSHandler{challenges: challenges}
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Echo EDNS OPT record if present in the query
	if opt := r.IsEdns0(); opt != nil {
		edns := new(dns.OPT)
		edns.Hdr.Name = "."
		edns.Hdr.Rrtype = dns.TypeOPT
		edns.SetUDPSize(opt.UDPSize())
		msg.Extra = append(msg.Extra, edns)
	}

	for _, q := range r.Question {
		name := strings.ToLower(q.Name)
		domainLower := strings.ToLower(cfg.Domain)

		if cfg.Verbose {
			log.Printf("[dns] query: %s %s", dns.TypeToString[q.Qtype], name)
		}

		if !strings.HasSuffix(name, domainLower) {
			continue
		}

		// Handle ACME DNS-01 challenges
		if q.Qtype == dns.TypeTXT {
			acmePrefix := "_acme-challenge." + domainLower
			if name == acmePrefix || strings.HasSuffix(name, "."+acmePrefix) {
				if token := h.challenges.Get(); token != "" {
					msg.Answer = append(msg.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
						Txt: []string{token},
					})
					if cfg.Verbose {
						log.Printf("[dns] ACME challenge response: %s", token[:min(16, len(token))]+"...")
					}
				}
				continue
			}
		}

		// Handle SOA
		if q.Qtype == dns.TypeSOA {
			msg.Answer = append(msg.Answer, &dns.SOA{
				Hdr:     dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: cfg.TTL},
				Ns:      cfg.NS[0],
				Mbox:    "admin." + cfg.Domain,
				Serial:  1,
				Refresh: 86400,
				Retry:   7200,
				Expire:  3600000,
				Minttl:  300, // negative cache TTL: 5 minutes (important for ACME challenges)
			})
			continue
		}

		// Handle NS
		if q.Qtype == dns.TypeNS && name == domainLower {
			for _, ns := range cfg.NS {
				msg.Answer = append(msg.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: cfg.Domain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: cfg.TTL},
					Ns:  ns,
				})
			}
			continue
		}

		// Strip domain suffix to get subdomain
		sub := strings.TrimSuffix(name, domainLower)
		sub = strings.TrimSuffix(sub, ".")

		if sub == "" {
			continue
		}

		ip := extractIP(sub)
		if ip == nil {
			continue
		}

		if cfg.OnlyPrivate && !isPrivateIP(ip) {
			if cfg.Verbose {
				log.Printf("[dns] rejected non-private IP: %s", ip)
			}
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			if ipv4 := ip.To4(); ipv4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: cfg.TTL},
					A:   ipv4,
				})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: cfg.TTL},
					AAAA: ip,
				})
			}
		case dns.TypeANY:
			if ipv4 := ip.To4(); ipv4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: cfg.TTL},
					A:   ipv4,
				})
			} else {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: cfg.TTL},
					AAAA: ip,
				})
			}
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dns] write error: %v", err)
	}
}

// StartDNS starts UDP and TCP DNS servers.
func StartDNS(addr string, handler *DNSHandler) {
	go func() {
		log.Printf("[dns] listening on %s (UDP)", addr)
		if err := (&dns.Server{Addr: addr, Net: "udp", Handler: handler}).ListenAndServe(); err != nil {
			log.Fatalf("[dns] UDP failed: %v", err)
		}
	}()
	go func() {
		log.Printf("[dns] listening on %s (TCP)", addr)
		if err := (&dns.Server{Addr: addr, Net: "tcp", Handler: handler}).ListenAndServe(); err != nil {
			log.Fatalf("[dns] TCP failed: %v", err)
		}
	}()
}

// --- Private IP check ---

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, n)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
