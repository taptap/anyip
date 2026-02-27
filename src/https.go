package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// StartHTTPS starts the HTTPS server for DoH and certificate distribution.
// Uses dynamic certificate loading so the server starts immediately and picks
// up the certificate as soon as ACME issuance completes — no restart needed.
func StartHTTPS(addr string, dnsHandler *DNSHandler, certMgr *CertManager) {
	mux := http.NewServeMux()

	// DoH endpoint
	mux.HandleFunc(cfg.DOHPath, dohHandler(dnsHandler))

	// Certificate distribution
	mux.HandleFunc("/cert/fullchain.pem", certFileHandler(certMgr.certFile, "application/x-pem-file"))
	mux.HandleFunc("/cert/privkey.pem", certFileHandler(certMgr.keyFile, "application/x-pem-file"))
	mux.HandleFunc("/cert/info", certInfoHandler(certMgr))

	// Subdomain certificate distribution
	mux.HandleFunc("/cert/sub/", subCertHandler(certMgr))

	// Root
	mux.HandleFunc("/", handleRoot)

	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := strings.ToLower(hello.ServerName)
			domain := strings.TrimSuffix(strings.ToLower(cfg.Domain), ".")

			// Multi-level subdomain → try per-label cert
			// e.g., foo.127-0-0-1.anyip.dev → label "127-0-0-1"
			if strings.HasSuffix(serverName, "."+domain) {
				sub := strings.TrimSuffix(serverName, "."+domain)
				labels := strings.Split(sub, ".")
				if len(labels) >= 2 {
					label := strings.Join(labels[1:], ".")
					cf, kf := certMgr.SubdomainCertFiles(label)
					if cert, err := tls.LoadX509KeyPair(cf, kf); err == nil {
						return &cert, nil
					}
				}
			}

			// Fall back to root cert
			certFile, keyFile := certMgr.CertFiles()
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("certificate not yet available: %w", err)
			}
			return &cert, nil
		},
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	go func() {
		log.Printf("[https] listening on %s (TLS with dynamic cert loading)", addr)
		// TLS certs are loaded dynamically via GetCertificate, so pass empty strings.
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("[https] server failed: %v", err)
		}
	}()
}

// --- DoH Handlers ---

func dohHandler(h *DNSHandler) http.HandlerFunc {
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

func handleDoHGet(w http.ResponseWriter, r *http.Request, h *DNSHandler) {
	name := r.URL.Query().Get("name")
	qtype := r.URL.Query().Get("type")
	if name == "" {
		http.Error(w, `{"error":"missing 'name' parameter"}`, http.StatusBadRequest)
		return
	}
	if qtype == "" {
		qtype = "A"
	}

	dnsType, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		http.Error(w, `{"error":"invalid 'type' parameter"}`, http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, dnsType)

	recorder := &responseRecorder{}
	h.ServeDNS(recorder, msg)

	resp := recorder.msg
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetReply(msg)
	}

	jsonResp := buildDOHJSON(resp)
	w.Header().Set("Content-Type", "application/dns-json")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", cfg.TTL))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(jsonResp)
}

func handleDoHPost(w http.ResponseWriter, r *http.Request, h *DNSHandler) {
	ct := r.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	buf, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
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
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", cfg.TTL))
	w.Write(packed)
}

// --- Certificate Distribution ---

func certFileHandler(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "certificate not available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
	}
}

func certInfoHandler(certMgr *CertManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := certMgr.CertInfoJSON()
		if err != nil {
			http.Error(w, `{"error":"certificate not available"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
	}
}

func subCertHandler(certMgr *CertManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse path: /cert/sub/{label}[/{action}]
		path := strings.TrimPrefix(r.URL.Path, "/cert/sub/")
		parts := strings.SplitN(path, "/", 2)
		label := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}

		if label == "" {
			http.Error(w, `{"error":"missing label"}`, http.StatusBadRequest)
			return
		}

		// Validate label is a valid IP pattern
		if extractIP(label) == nil {
			http.Error(w, `{"error":"invalid IP label"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")

		switch {
		case r.Method == http.MethodPost && action == "":
			// Check whitelist before issuance
			if !cfg.CertSubs[label] {
				http.Error(w, `{"error":"label not in allowed list"}`, http.StatusForbidden)
				return
			}
			// Request cert issuance
			if err := certMgr.RequestSubdomainCert(label); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
			data, err := certMgr.SubdomainCertInfoJSON(label)
			if err != nil {
				http.Error(w, `{"error":"cert issued but info unavailable"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)

		case action == "fullchain.pem":
			certFile, _ := certMgr.SubdomainCertFiles(label)
			data, err := os.ReadFile(certFile)
			if err != nil {
				http.Error(w, "certificate not available", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(data)

		case action == "privkey.pem":
			_, keyFile := certMgr.SubdomainCertFiles(label)
			data, err := os.ReadFile(keyFile)
			if err != nil {
				http.Error(w, "key not available", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(data)

		case action == "info":
			data, err := certMgr.SubdomainCertInfoJSON(label)
			if err != nil {
				http.Error(w, `{"error":"certificate not available"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)

		default:
			http.NotFound(w, r)
		}
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	domain := strings.TrimSuffix(cfg.Domain, ".")

	// Redirect bare domain to www (for GitHub Pages)
	if strings.EqualFold(r.Host, domain) {
		http.Redirect(w, r, "https://www."+domain+"/", http.StatusMovedPermanently)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Header
	fmt.Fprintf(w, "AnyIP\n")
	fmt.Fprintf(w, "=====\n")
	fmt.Fprintf(w, "DNS server that resolves IP addresses embedded in hostnames.\n")
	fmt.Fprintf(w, "Domain: %s\n", domain)
	fmt.Fprintf(w, "\n")

	// DNS Resolution (always available)
	fmt.Fprintf(w, "%s\n\n", sectionHeader("DNS Resolution"))
	fmt.Fprintf(w, "  Format:\n")
	fmtRows := [][3]string{
		{"IPv4:", fmt.Sprintf("{prefix}-{a}-{b}-{c}-{d}.%s", domain), "a.b.c.d"},
		{"IPv6:", fmt.Sprintf("2001-db8--1.%s", domain), "2001:db8::1"},
		{"Nested:", fmt.Sprintf("{any}.{ip-label}.%s", domain), "same IP"},
	}
	fmtMax := 0
	for _, r := range fmtRows {
		if l := len(r[1]); l > fmtMax {
			fmtMax = l
		}
	}
	const labelW = 10 // "Example: " + padding
	fmt.Fprintf(w, "    %-*s%-*s  ->  %s\n", labelW, fmtRows[0][0], fmtMax, fmtRows[0][1], fmtRows[0][2])
	fmt.Fprintf(w, "    %-*sdashes replace colons, double-dash for \"::\" compression\n", labelW, fmtRows[1][0])
	fmt.Fprintf(w, "    %-*s%-*s  ->  %s\n", labelW, "Example:", fmtMax, fmtRows[1][1], fmtRows[1][2])
	fmt.Fprintf(w, "    %-*s%-*s  ->  %s\n", labelW, fmtRows[2][0], fmtMax, fmtRows[2][1], fmtRows[2][2])
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  Examples:\n")
	digExamples := [][2]string{
		{"127-0-0-1." + domain, "127.0.0.1"},
		{"myapp-192-168-1-5." + domain, "192.168.1.5"},
		{"user1.127-0-0-1." + domain, "127.0.0.1"},
	}
	digMax := 0
	for _, ex := range digExamples {
		if l := len("dig " + ex[0] + " +short"); l > digMax {
			digMax = l
		}
	}
	for _, ex := range digExamples {
		cmd := "dig " + ex[0] + " +short"
		fmt.Fprintf(w, "    %-*s  ->  %s\n", digMax, cmd, ex[1])
	}
	if cfg.OnlyPrivate {
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  NOTE: This instance only resolves private/reserved IPs.\n")
		fmt.Fprintf(w, "  Allowed ranges:\n")
		privateRanges := [][2]string{
			{"10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16", "RFC 1918"},
			{"127.0.0.0/8", "loopback"},
			{"100.64.0.0/10", "CGNAT/Tailscale"},
			{"169.254.0.0/16", "link-local"},
			{"fc00::/7, fe80::/10, ::1/128", "IPv6 private"},
		}
		prMax := 0
		for _, r := range privateRanges {
			if l := len(r[0]); l > prMax {
				prMax = l
			}
		}
		for _, r := range privateRanges {
			fmt.Fprintf(w, "    - %-*s  (%s)\n", prMax, r[0], r[1])
		}
		fmt.Fprintf(w, "  Public IPs will return empty (NODATA) responses.\n")
	}
	fmt.Fprintf(w, "\n")

	// Static CNAME records
	if len(cfg.CNAME) > 0 {
		fmt.Fprintf(w, "%s\n\n", sectionHeader("Static CNAME Records"))
		labels := make([]string, 0, len(cfg.CNAME))
		for l := range cfg.CNAME {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		maxW := 0
		for _, label := range labels {
			if w := len(label) + 1 + len(domain); w > maxW {
				maxW = w
			}
		}
		for _, label := range labels {
			entry := fmt.Sprintf("%s.%s", label, domain)
			fmt.Fprintf(w, "  %-*s  ->  %s\n", maxW, entry, strings.TrimSuffix(cfg.CNAME[label], "."))
		}
		fmt.Fprintf(w, "\n")
	}

	// Wildcard Certificate (only when ACME is configured)
	acmeEnabled := cfg.ACMEEmail != ""
	if acmeEnabled {
		fmt.Fprintf(w, "%s\n\n", sectionHeader(fmt.Sprintf("Wildcard Certificate (*.%s)", domain)))
		fmt.Fprintf(w, "  Auto-provisioned via Let's Encrypt.\n\n")
		fmt.Fprintf(w, "  Endpoints:\n")
		fmt.Fprintf(w, "    GET  /cert/fullchain.pem   PEM certificate chain\n")
		fmt.Fprintf(w, "    GET  /cert/privkey.pem     PEM private key\n")
		fmt.Fprintf(w, "    GET  /cert/info            JSON metadata (issuer, expiry, SANs)\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  Example:\n")
		fmt.Fprintf(w, "    $ curl https://%s/cert/fullchain.pem -o fullchain.pem\n", domain)
		fmt.Fprintf(w, "    $ curl https://%s/cert/privkey.pem -o privkey.pem\n", domain)
		fmt.Fprintf(w, "\n")
	}

	// Subdomain Certificates (only when ACME + cert-subs configured)
	if acmeEnabled && len(cfg.CertSubs) > 0 {
		labels := make([]string, 0, len(cfg.CertSubs))
		for l := range cfg.CertSubs {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		example := labels[0]

		fmt.Fprintf(w, "%s\n\n", sectionHeader(fmt.Sprintf("Subdomain Certificates (*.{ip}.%s)", domain)))
		fmt.Fprintf(w, "  On-demand wildcard certs for per-IP subdomains.\n")
		fmt.Fprintf(w, "  Allowed labels: %s\n\n", strings.Join(labels, ", "))
		fmt.Fprintf(w, "  Endpoints (replace {label} with an allowed IP label):\n")
		fmt.Fprintf(w, "    POST /cert/sub/{label}                Issue new certificate (JSON)\n")
		fmt.Fprintf(w, "    GET  /cert/sub/{label}/fullchain.pem  PEM certificate chain\n")
		fmt.Fprintf(w, "    GET  /cert/sub/{label}/privkey.pem    PEM private key\n")
		fmt.Fprintf(w, "    GET  /cert/sub/{label}/info           JSON metadata\n")
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  Example:\n")
		fmt.Fprintf(w, "    $ curl -X POST https://%s/cert/sub/%s\n", domain, example)
		fmt.Fprintf(w, "    $ curl https://%s/cert/sub/%s/fullchain.pem -o fullchain.pem\n", domain, example)
		fmt.Fprintf(w, "\n")
	}

	// DNS over HTTPS (always available when HTTPS server runs)
	fmt.Fprintf(w, "%s\n\n", sectionHeader("DNS over HTTPS (RFC 8484)"))
	fmt.Fprintf(w, "  Endpoint: %s\n\n", cfg.DOHPath)
	fmt.Fprintf(w, "    GET  %s?name={hostname}&type={A|AAAA|CNAME}\n", cfg.DOHPath)
	fmt.Fprintf(w, "         Response: application/dns-json\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "    POST %s\n", cfg.DOHPath)
	fmt.Fprintf(w, "         Content-Type: application/dns-message\n")
	fmt.Fprintf(w, "         Response:     application/dns-message\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  Example:\n")
	fmt.Fprintf(w, "    $ curl \"https://%s%s?name=127-0-0-1.%s&type=A\"\n", domain, cfg.DOHPath, domain)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 72))
	fmt.Fprintf(w, "Source: https://github.com/taptap/anyip\n")
}

// sectionHeader returns a formatted section header padded to 72 chars.
func sectionHeader(title string) string {
	prefix := "-- " + title + " "
	pad := 72 - len(prefix)
	if pad < 3 {
		pad = 3
	}
	return prefix + strings.Repeat("-", pad)
}

// --- DoH JSON types ---

type dohJSON struct {
	Status   int              `json:"Status"`
	TC       bool             `json:"TC"`
	RD       bool             `json:"RD"`
	RA       bool             `json:"RA"`
	AD       bool             `json:"AD"`
	CD       bool             `json:"CD"`
	Question []dohJSONQ       `json:"Question"`
	Answer   []dohJSONAnswer  `json:"Answer,omitempty"`
}

type dohJSONQ struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type dohJSONAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

func buildDOHJSON(resp *dns.Msg) dohJSON {
	j := dohJSON{
		Status: resp.Rcode,
		TC:     resp.Truncated,
		RD:     resp.RecursionDesired,
		RA:     resp.RecursionAvailable,
		AD:     resp.AuthenticatedData,
		CD:     resp.CheckingDisabled,
	}
	for _, q := range resp.Question {
		j.Question = append(j.Question, dohJSONQ{Name: q.Name, Type: q.Qtype})
	}
	for _, a := range resp.Answer {
		hdr := a.Header()
		var data string
		switch rr := a.(type) {
		case *dns.A:
			data = rr.A.String()
		case *dns.AAAA:
			data = rr.AAAA.String()
		case *dns.CNAME:
			data = rr.Target
		case *dns.TXT:
			data = strings.Join(rr.Txt, " ")
		default:
			data = a.String()
		}
		j.Answer = append(j.Answer, dohJSONAnswer{
			Name: hdr.Name, Type: hdr.Rrtype, TTL: hdr.Ttl, Data: data,
		})
	}
	return j
}

// --- Response recorder for DoH ---

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
