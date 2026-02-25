package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var (
	domain  string
	ttl     uint32
	verbose bool
)

func main() {
	var (
		dnsAddr string
		dohAddr string
		dohPath string
		tlsCert string
		tlsKey  string
	)

	flag.StringVar(&domain, "domain", envOr("ANYIP_DOMAIN", "anyip.dev"), "Base domain")
	flag.StringVar(&dnsAddr, "dns-addr", envOr("ANYIP_DNS_ADDR", ":53"), "DNS listen address (UDP+TCP)")
	flag.StringVar(&dohAddr, "doh-addr", envOr("ANYIP_DOH_ADDR", ":443"), "DoH listen address (HTTPS), empty to disable")
	flag.StringVar(&dohPath, "doh-path", envOr("ANYIP_DOH_PATH", "/dns-query"), "DoH endpoint path")
	flag.StringVar(&tlsCert, "tls-cert", envOr("ANYIP_TLS_CERT", ""), "TLS certificate path")
	flag.StringVar(&tlsKey, "tls-key", envOr("ANYIP_TLS_KEY", ""), "TLS private key path")
	flag.BoolVar(&verbose, "verbose", envOr("ANYIP_VERBOSE", "false") == "true", "Verbose logging")

	var ttlVal uint
	flag.UintVar(&ttlVal, "ttl", 259200, "Response TTL in seconds (default: 72h)")
	flag.Parse()
	ttl = uint32(ttlVal)

	// Ensure domain has trailing dot for DNS
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	handler := &dnsHandler{}

	// Start DNS servers (UDP + TCP)
	if dnsAddr != "" {
		udpServer := &dns.Server{Addr: dnsAddr, Net: "udp", Handler: handler}
		tcpServer := &dns.Server{Addr: dnsAddr, Net: "tcp", Handler: handler}

		go func() {
			log.Printf("[dns] listening on %s (UDP)", dnsAddr)
			if err := udpServer.ListenAndServe(); err != nil {
				log.Fatalf("[dns] UDP server failed: %v", err)
			}
		}()
		go func() {
			log.Printf("[dns] listening on %s (TCP)", dnsAddr)
			if err := tcpServer.ListenAndServe(); err != nil {
				log.Fatalf("[dns] TCP server failed: %v", err)
			}
		}()
	}

	// Start DoH server
	if dohAddr != "" && tlsCert != "" && tlsKey != "" {
		mux := http.NewServeMux()
		mux.HandleFunc(dohPath, dohHandler(handler))
		mux.HandleFunc("/", handleRoot)

		go func() {
			log.Printf("[doh] listening on %s (HTTPS)", dohAddr)
			if err := http.ListenAndServeTLS(dohAddr, tlsCert, tlsKey, mux); err != nil {
				log.Fatalf("[doh] HTTPS server failed: %v", err)
			}
		}()
	} else if dohAddr != "" {
		log.Printf("[doh] disabled (no TLS certificate configured)")
	}

	log.Printf("[anyip] serving domain: %s (TTL: %ds)", domain, ttl)

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[anyip] shutting down")
}

// --- DNS Handler ---

type dnsHandler struct{}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		name := strings.ToLower(q.Name)

		if verbose {
			log.Printf("[dns] query: %s %s", dns.TypeToString[q.Qtype], name)
		}

		// Only handle queries under our domain
		if !strings.HasSuffix(name, strings.ToLower(domain)) {
			continue
		}

		// Strip domain suffix to get the subdomain part
		sub := strings.TrimSuffix(name, strings.ToLower(domain))
		sub = strings.TrimSuffix(sub, ".")

		ip := extractIP(sub)
		if ip == nil {
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			if ipv4 := ip.To4(); ipv4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ipv4,
				})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil { // IPv6 only
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
		case dns.TypeANY:
			if ipv4 := ip.To4(); ipv4 != nil {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ipv4,
				})
			} else {
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dns] write error: %v", err)
	}
}

// --- IP Extraction ---

// extractIP scans labels right-to-left to find an embedded IP address.
// IPv4: "192-168-1-50" → 192.168.1.50
// IPv6: "2001-db8--1" → 2001:db8::1 (-- means ::)
func extractIP(subdomain string) net.IP {
	if subdomain == "" {
		return nil
	}

	labels := strings.Split(subdomain, ".")

	// Scan from right to find the IP portion
	// Try progressively longer sequences from the right
	for i := len(labels) - 1; i >= 0; i-- {
		candidate := strings.Join(labels[i:], ".")
		if ip := parseEmbeddedIP(candidate); ip != nil {
			return ip
		}
	}
	return nil
}

func parseEmbeddedIP(s string) net.IP {
	// Try IPv4: exactly 4 dash-separated decimal octets
	if ip := tryIPv4(s); ip != nil {
		return ip
	}

	// Try IPv6: contains dashes, convert -- to :: and - to :
	if ip := tryIPv6(s); ip != nil {
		return ip
	}

	return nil
}

func tryIPv4(s string) net.IP {
	parts := strings.Split(s, "-")
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

func tryIPv6(s string) net.IP {
	if !strings.Contains(s, "-") {
		return nil
	}

	// Replace -- with :: (compressed zero groups)
	ipStr := strings.ReplaceAll(s, "--", "::")
	// Replace remaining - with :
	ipStr = strings.ReplaceAll(ipStr, "-", ":")

	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() != nil {
		return nil // Not a valid IPv6, or it's actually IPv4
	}
	return ip
}

// --- DoH Handler ---

func dohHandler(h *dnsHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleDoHGet(w, r, h)
		case http.MethodPost:
			handleDoHPost(w, r, h)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleDoHGet handles JSON-style DoH queries (application/dns-json)
func handleDoHGet(w http.ResponseWriter, r *http.Request, h *dnsHandler) {
	name := r.URL.Query().Get("name")
	qtype := r.URL.Query().Get("type")
	if name == "" {
		http.Error(w, "missing 'name' parameter", http.StatusBadRequest)
		return
	}
	if qtype == "" {
		qtype = "A"
	}

	dnsType, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		http.Error(w, "invalid 'type' parameter", http.StatusBadRequest)
		return
	}

	// Ensure FQDN
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, dnsType)

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true

	// Use the DNS handler to populate the response
	recorder := &responseRecorder{}
	h.ServeDNS(recorder, msg)
	if recorder.msg != nil {
		resp = recorder.msg
	}

	// Convert to JSON response
	jsonResp := dohJSONResponse{
		Status: 0,
		TC:     resp.Truncated,
		RD:     resp.RecursionDesired,
		RA:     resp.RecursionAvailable,
		AD:     resp.AuthenticatedData,
		CD:     resp.CheckingDisabled,
	}

	for _, q := range resp.Question {
		jsonResp.Question = append(jsonResp.Question, dohJSONQuestion{
			Name: q.Name,
			Type: q.Qtype,
		})
	}

	for _, a := range resp.Answer {
		hdr := a.Header()
		var data string
		switch rr := a.(type) {
		case *dns.A:
			data = rr.A.String()
		case *dns.AAAA:
			data = rr.AAAA.String()
		default:
			data = a.String()
		}
		jsonResp.Answer = append(jsonResp.Answer, dohJSONAnswer{
			Name: hdr.Name,
			Type: hdr.Rrtype,
			TTL:  hdr.Ttl,
			Data: data,
		})
	}

	w.Header().Set("Content-Type", "application/dns-json")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", ttl))
	json.NewEncoder(w).Encode(jsonResp)
}

// handleDoHPost handles wire-format DoH queries (application/dns-message)
func handleDoHPost(w http.ResponseWriter, r *http.Request, h *dnsHandler) {
	if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	buf := make([]byte, 65535)
	n, err := r.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(buf[:n]); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}

	recorder := &responseRecorder{}
	h.ServeDNS(recorder, msg)

	if recorder.msg == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}

	packed, err := recorder.msg.Pack()
	if err != nil {
		http.Error(w, "failed to pack response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", ttl))
	w.Write(packed)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "AnyIP DNS Server\nhttps://github.com/nicedraft/anyip\n")
}

// --- DoH Types ---

type dohJSONResponse struct {
	Status   int               `json:"Status"`
	TC       bool              `json:"TC"`
	RD       bool              `json:"RD"`
	RA       bool              `json:"RA"`
	AD       bool              `json:"AD"`
	CD       bool              `json:"CD"`
	Question []dohJSONQuestion `json:"Question"`
	Answer   []dohJSONAnswer   `json:"Answer,omitempty"`
}

type dohJSONQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type dohJSONAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

// responseRecorder captures DNS responses for DoH
type responseRecorder struct {
	msg *dns.Msg
}

func (r *responseRecorder) LocalAddr() net.Addr       { return nil }
func (r *responseRecorder) RemoteAddr() net.Addr      { return nil }
func (r *responseRecorder) WriteMsg(m *dns.Msg) error { r.msg = m; return nil }
func (r *responseRecorder) Write([]byte) (int, error)  { return 0, nil }
func (r *responseRecorder) Close() error               { return nil }
func (r *responseRecorder) TsigStatus() error          { return nil }
func (r *responseRecorder) TsigTimersOnly(bool)        {}
func (r *responseRecorder) Hijack()                    {}

// --- Helpers ---

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
