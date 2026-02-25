package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func setupHTTPSTest() *DNSHandler {
	cfg = Config{
		Domain:   "test.dev.",
		TTL:      300,
		NS:       []string{"ns1.test.dev."},
		DomainIP: net.ParseIP("1.2.3.4"),
		CNAME:    map[string]string{"www": "example.github.io."},
		CertSubs: map[string]bool{},
	}
	return NewDNSHandler(NewChallengeStore())
}

func TestHandleRoot_BareDomainRedirect(t *testing.T) {
	setupHTTPSTest()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "test.dev"
	w := httptest.NewRecorder()
	handleRoot(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	loc := w.Header().Get("Location")
	if loc != "https://www.test.dev/" {
		t.Errorf("Location = %s, want https://www.test.dev/", loc)
	}
}

func TestHandleRoot_InfoPage(t *testing.T) {
	setupHTTPSTest()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127-0-0-1.test.dev"
	w := httptest.NewRecorder()
	handleRoot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %s, want text/plain", ct)
	}
	if !strings.Contains(w.Body.String(), "AnyIP") {
		t.Error("body does not contain 'AnyIP'")
	}
}

func TestHandleRoot_NotFound(t *testing.T) {
	setupHTTPSTest()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	req.Host = "test.dev"
	w := httptest.NewRecorder()
	handleRoot(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDoHGet_BasicA(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("GET", "/dns-query?name=127-0-0-1.test.dev&type=A", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp dohJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if resp.Answer[0].Data != "127.0.0.1" {
		t.Errorf("data = %s, want 127.0.0.1", resp.Answer[0].Data)
	}
}

func TestDoHGet_CNAME(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("GET", "/dns-query?name=www.test.dev&type=CNAME", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp dohJSON
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if resp.Answer[0].Data != "example.github.io." {
		t.Errorf("data = %s, want example.github.io.", resp.Answer[0].Data)
	}
	if resp.Answer[0].Type != dns.TypeCNAME {
		t.Errorf("type = %d, want %d (CNAME)", resp.Answer[0].Type, dns.TypeCNAME)
	}
}

func TestDoHGet_MissingName(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("GET", "/dns-query?type=A", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDoHGet_InvalidType(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("GET", "/dns-query?name=test.dev&type=INVALID", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDoHGet_DefaultType(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("GET", "/dns-query?name=127-0-0-1.test.dev", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp dohJSON
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if resp.Answer[0].Type != dns.TypeA {
		t.Errorf("type = %d, want %d (A)", resp.Answer[0].Type, dns.TypeA)
	}
}

func TestDoHPost(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	msg := new(dns.Msg)
	msg.SetQuestion("127-0-0-1.test.dev.", dns.TypeA)
	packed, _ := msg.Pack()

	req := httptest.NewRequest("POST", "/dns-query", strings.NewReader(string(packed)))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(w.Body.Bytes()); err != nil {
		t.Fatalf("failed to unpack response: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "127.0.0.1" {
		t.Errorf("got %s, want 127.0.0.1", a.A.String())
	}
}

func TestDoHPost_WrongContentType(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("POST", "/dns-query", strings.NewReader("garbage"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
}

func TestDoH_MethodNotAllowed(t *testing.T) {
	handler := setupHTTPSTest()
	h := dohHandler(handler)

	req := httptest.NewRequest("PUT", "/dns-query", nil)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestBuildDOHJSON(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("test.dev.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.test.dev.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4").To4(),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "aaaa.test.dev.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		},
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.test.dev.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "example.com.",
		},
		&dns.TXT{
			Hdr: dns.RR_Header{Name: "txt.test.dev.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"hello", "world"},
		},
	}

	j := buildDOHJSON(msg)

	if len(j.Answer) != 4 {
		t.Fatalf("got %d answers, want 4", len(j.Answer))
	}

	tests := []struct {
		idx      int
		wantType uint16
		wantData string
	}{
		{0, dns.TypeA, "1.2.3.4"},
		{1, dns.TypeAAAA, "2001:db8::1"},
		{2, dns.TypeCNAME, "example.com."},
		{3, dns.TypeTXT, "hello world"},
	}
	for _, tt := range tests {
		a := j.Answer[tt.idx]
		if a.Type != tt.wantType {
			t.Errorf("answer[%d] type = %d, want %d", tt.idx, a.Type, tt.wantType)
		}
		if a.Data != tt.wantData {
			t.Errorf("answer[%d] data = %s, want %s", tt.idx, a.Data, tt.wantData)
		}
	}
}
