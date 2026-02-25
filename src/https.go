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

	// Root
	mux.HandleFunc("/", handleRoot)

	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	domain := strings.TrimSuffix(cfg.Domain, ".")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "AnyIP - DNS server for development HTTPS\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  dig 127-0-0-1.%s +short          → 127.0.0.1\n", domain)
	fmt.Fprintf(w, "  dig myapp-192-168-1-5.%s +short   → 192.168.1.5\n", domain)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Certificates:\n")
	fmt.Fprintf(w, "  curl https://%s/cert/fullchain.pem\n", domain)
	fmt.Fprintf(w, "  curl https://%s/cert/privkey.pem\n", domain)
	fmt.Fprintf(w, "  curl https://%s/cert/info\n", domain)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "DNS over HTTPS:\n")
	fmt.Fprintf(w, "  https://%s/dns-query\n", domain)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "https://github.com/taptap/anyip\n")
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
