package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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
	TTL         uint32
	OnlyPrivate bool
	Verbose     bool
}

func main() {
	var ttlVal uint
	flag.StringVar(&cfg.Domain, "domain", envOr("ANYIP_DOMAIN", "anyip.dev"), "Base domain")
	flag.StringVar(&cfg.DNSAddr, "dns-addr", envOr("ANYIP_DNS_ADDR", ":53"), "DNS listen address (UDP+TCP)")
	flag.StringVar(&cfg.DOHAddr, "doh-addr", envOr("ANYIP_DOH_ADDR", ":443"), "DoH + cert distribution (HTTPS)")
	flag.StringVar(&cfg.DOHPath, "doh-path", envOr("ANYIP_DOH_PATH", "/dns-query"), "DoH endpoint path")
	flag.StringVar(&cfg.ACMEEmail, "acme-email", envOr("ANYIP_ACME_EMAIL", ""), "Email for Let's Encrypt")
	flag.BoolVar(&cfg.ACMEStaging, "acme-staging", envOr("ANYIP_ACME_STAGING", "false") == "true", "Use LE staging")
	flag.StringVar(&cfg.CertDir, "cert-dir", envOr("ANYIP_CERT_DIR", "./certs"), "Certificate storage directory")
	flag.UintVar(&ttlVal, "ttl", envOrUint("ANYIP_TTL", 259200), "DNS response TTL in seconds (72h)")
	flag.BoolVar(&cfg.OnlyPrivate, "only-private", envOr("ANYIP_ONLY_PRIVATE", "false") == "true", "Only resolve private IPs")
	flag.BoolVar(&cfg.Verbose, "verbose", envOr("ANYIP_VERBOSE", "false") == "true", "Verbose logging")
	flag.Parse()
	cfg.TTL = uint32(ttlVal)

	// Ensure domain has trailing dot for DNS
	if !strings.HasSuffix(cfg.Domain, ".") {
		cfg.Domain = cfg.Domain + "."
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
