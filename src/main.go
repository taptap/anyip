package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/joho/godotenv"
)

var cfg Config

type Config struct {
	Domain      string
	DNSAddr     string
	DOHAddr     string
	DOHPath     string
	ACMEEmail   string
	ACMEStaging bool
	CertDir     string
	NS          []string
	DomainIP    net.IP
	TTL         uint32
	OnlyPrivate bool
	Verbose     bool
	CertSubs    map[string]bool   // allowed IP labels for subdomain certs
	CNAME       map[string]string // static CNAME records: label → target
}

func main() {
	// Load .env file if present (does not override existing env vars)
	_ = godotenv.Load()

	var ttlVal uint
	var nsStr, domainIPStr, certSubsStr, cnameStr string
	flag.StringVar(&cfg.Domain, "domain", envOr("ANYIP_DOMAIN", "anyip.dev"), "Base domain")
	flag.StringVar(&domainIPStr, "domain-ip", envOr("ANYIP_DOMAIN_IP", ""), "IP address for bare domain resolution")
	flag.StringVar(&nsStr, "ns", envOr("ANYIP_NS", ""), "Nameservers (comma-separated, e.g. ns1.example.com,ns2.example.com)")
	flag.StringVar(&cfg.DNSAddr, "dns-addr", envOr("ANYIP_DNS_ADDR", ":53"), "DNS listen address (UDP+TCP)")
	flag.StringVar(&cfg.DOHAddr, "doh-addr", envOr("ANYIP_DOH_ADDR", ":443"), "DoH + cert distribution (HTTPS)")
	flag.StringVar(&cfg.DOHPath, "doh-path", envOr("ANYIP_DOH_PATH", "/dns-query"), "DoH endpoint path")
	flag.StringVar(&cfg.ACMEEmail, "acme-email", envOr("ANYIP_ACME_EMAIL", ""), "Email for Let's Encrypt")
	flag.BoolVar(&cfg.ACMEStaging, "acme-staging", envOr("ANYIP_ACME_STAGING", "false") == "true", "Use LE staging")
	flag.StringVar(&cfg.CertDir, "cert-dir", envOr("ANYIP_CERT_DIR", "./certs"), "Certificate storage directory")
	flag.UintVar(&ttlVal, "ttl", envOrUint("ANYIP_TTL", 259200), "DNS response TTL in seconds (72h)")
	flag.BoolVar(&cfg.OnlyPrivate, "only-private", envOr("ANYIP_ONLY_PRIVATE", "false") == "true", "Only resolve private IPs")
	flag.StringVar(&certSubsStr, "cert-subs", envOr("ANYIP_CERT_SUBS", ""), "Allowed IP labels for subdomain certs (comma-separated, e.g. 127-0-0-1)")
	flag.StringVar(&cnameStr, "cname", envOr("ANYIP_CNAME", ""), "Static CNAME records (comma-separated label=target, e.g. www=taptap.github.io)")
	flag.BoolVar(&cfg.Verbose, "verbose", envOr("ANYIP_VERBOSE", "false") == "true", "Verbose logging")
	flag.Parse()
	cfg.TTL = uint32(ttlVal)

	// Parse allowed subdomain cert labels
	cfg.CertSubs = make(map[string]bool)
	if certSubsStr != "" {
		for _, label := range strings.Split(certSubsStr, ",") {
			label = strings.TrimSpace(label)
			if label != "" {
				cfg.CertSubs[label] = true
			}
		}
	}

	// Parse static CNAME records
	cfg.CNAME = make(map[string]string)
	if cnameStr != "" {
		for _, entry := range strings.Split(cnameStr, ",") {
			entry = strings.TrimSpace(entry)
			if parts := strings.SplitN(entry, "=", 2); len(parts) == 2 {
				label := strings.TrimSpace(parts[0])
				target := strings.TrimSpace(parts[1])
				if label != "" && target != "" {
					if !strings.HasSuffix(target, ".") {
						target = target + "."
					}
					cfg.CNAME[label] = target
				}
			}
		}
	}

	// Ensure domain has trailing dot for DNS
	if !strings.HasSuffix(cfg.Domain, ".") {
		cfg.Domain = cfg.Domain + "."
	}

	// Parse nameservers
	if nsStr != "" {
		for _, ns := range strings.Split(nsStr, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				if !strings.HasSuffix(ns, ".") {
					ns = ns + "."
				}
				cfg.NS = append(cfg.NS, ns)
			}
		}
	}
	if len(cfg.NS) == 0 {
		cfg.NS = []string{"ns1." + cfg.Domain, "ns2." + cfg.Domain}
	}

	// Parse domain IP
	if domainIPStr != "" {
		cfg.DomainIP = net.ParseIP(domainIPStr)
		if cfg.DomainIP == nil {
			log.Fatalf("[anyip] invalid domain IP: %s", domainIPStr)
		}
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		log.Fatalf("[anyip] failed to create cert dir: %v", err)
	}

	// ACME challenge store (shared between DNS handler and ACME manager)
	challenges := NewChallengeStore()

	// Start DNS server
	dnsHandler := NewDNSHandler(challenges)
	if cfg.DNSAddr != "" {
		StartDNS(cfg.DNSAddr, dnsHandler)
	}

	// ACME + HTTPS
	certMgr := NewCertManager(challenges)
	if cfg.ACMEEmail != "" {
		if err := certMgr.EnsureCertificate(); err != nil {
			log.Printf("[acme] initial certificate request failed: %v (will retry)", err)
		}
		go certMgr.AutoRenew()
	}

	if cfg.DOHAddr != "" {
		StartHTTPS(cfg.DOHAddr, dnsHandler, certMgr)
	}

	domainDisplay := strings.TrimSuffix(cfg.Domain, ".")
	log.Printf("[anyip] serving domain: %s (TTL: %ds)", domainDisplay, cfg.TTL)
	if cfg.OnlyPrivate {
		log.Printf("[anyip] restricted to private/reserved IPs only")
	}
	if cfg.ACMEEmail != "" {
		log.Printf("[anyip] ACME enabled (email: %s, staging: %v)", cfg.ACMEEmail, cfg.ACMEStaging)
	}
	if len(cfg.CertSubs) > 0 {
		labels := make([]string, 0, len(cfg.CertSubs))
		for l := range cfg.CertSubs {
			labels = append(labels, l)
		}
		log.Printf("[anyip] subdomain certs allowed for: %s", strings.Join(labels, ", "))
	}
	if len(cfg.CNAME) > 0 {
		entries := make([]string, 0, len(cfg.CNAME))
		for l, t := range cfg.CNAME {
			entries = append(entries, l+"→"+strings.TrimSuffix(t, "."))
		}
		log.Printf("[anyip] CNAME records: %s", strings.Join(entries, ", "))
	}

	fmt.Printf("\n  DNS:   %s (UDP+TCP)\n", cfg.DNSAddr)
	if cfg.DOHAddr != "" {
		fmt.Printf("  HTTPS: %s (DoH + cert distribution)\n", cfg.DOHAddr)
	}
	fmt.Printf("  Try:   dig @localhost 127-0-0-1.%s +short\n\n", domainDisplay)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[anyip] shutting down")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrUint(key string, fallback uint) uint {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint(n)
		}
	}
	return fallback
}
