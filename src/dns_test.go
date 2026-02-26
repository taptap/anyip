package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func setupDNSTest() (*DNSHandler, *ChallengeStore) {
	cfg = Config{
		Domain:   "test.dev.",
		TTL:      300,
		NS:       []string{"ns1.test.dev.", "ns2.test.dev."},
		DomainIP: net.ParseIP("1.2.3.4"),
		CNAME:    map[string]string{"www": "example.github.io."},
		CertSubs: map[string]bool{},
	}
	ch := NewChallengeStore()
	return NewDNSHandler(ch), ch
}

func queryDNS(handler *DNSHandler, name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	rec := &responseRecorder{}
	handler.ServeDNS(rec, msg)
	return rec.msg
}

func TestDNS_ARecord(t *testing.T) {
	handler, _ := setupDNSTest()
	tests := []struct {
		name string
		want string
	}{
		{"127-0-0-1.test.dev.", "127.0.0.1"},
		{"192-168-1-50.test.dev.", "192.168.1.50"},
		{"myapp-10-0-0-1.test.dev.", "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := queryDNS(handler, tt.name, dns.TypeA)
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(resp.Answer))
			}
			a, ok := resp.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
			}
			if a.A.String() != tt.want {
				t.Errorf("got %s, want %s", a.A.String(), tt.want)
			}
		})
	}
}

func TestDNS_AAAARecord(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "2001-db8--1.test.dev.", dns.TypeAAAA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", resp.Answer[0])
	}
	want := net.ParseIP("2001:db8::1")
	if !aaaa.AAAA.Equal(want) {
		t.Errorf("got %s, want %s", aaaa.AAAA, want)
	}
}

func TestDNS_TypeANY(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "127-0-0-1.test.dev.", dns.TypeANY)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.A); !ok {
		t.Fatalf("answer is %T, want *dns.A for IPv4", resp.Answer[0])
	}
}

func TestDNS_NestedSubdomain(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "app.127-0-0-1.test.dev.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.A.String() != "127.0.0.1" {
		t.Errorf("got %s, want 127.0.0.1", a.A.String())
	}
}

func TestDNS_BareDomainA(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "test.dev.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a := resp.Answer[0].(*dns.A)
	if a.A.String() != "1.2.3.4" {
		t.Errorf("got %s, want 1.2.3.4", a.A.String())
	}
}

func TestDNS_BareDomainAAAA(t *testing.T) {
	handler, _ := setupDNSTest()
	cfg.DomainIP = net.ParseIP("2001:db8::1")
	resp := queryDNS(handler, "test.dev.", dns.TypeAAAA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	aaaa := resp.Answer[0].(*dns.AAAA)
	want := net.ParseIP("2001:db8::1")
	if !aaaa.AAAA.Equal(want) {
		t.Errorf("got %s, want %s", aaaa.AAAA, want)
	}
}

func TestDNS_BareDomainANY(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "test.dev.", dns.TypeANY)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.A); !ok {
		t.Fatalf("answer is %T, want *dns.A for IPv4 DomainIP", resp.Answer[0])
	}
}

func TestDNS_SOA(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "test.dev.", dns.TypeSOA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	soa, ok := resp.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.SOA", resp.Answer[0])
	}
	if soa.Ns != "ns1.test.dev." {
		t.Errorf("NS = %s, want ns1.test.dev.", soa.Ns)
	}
	if soa.Mbox != "admin.test.dev." {
		t.Errorf("Mbox = %s, want admin.test.dev.", soa.Mbox)
	}
}

func TestDNS_NS(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "test.dev.", dns.TypeNS)
	if len(resp.Answer) != 2 {
		t.Fatalf("got %d answers, want 2", len(resp.Answer))
	}
	for i, want := range []string{"ns1.test.dev.", "ns2.test.dev."} {
		ns, ok := resp.Answer[i].(*dns.NS)
		if !ok {
			t.Fatalf("answer[%d] is %T, want *dns.NS", i, resp.Answer[i])
		}
		if ns.Ns != want {
			t.Errorf("answer[%d] NS = %s, want %s", i, ns.Ns, want)
		}
	}
}

func TestDNS_CNAME(t *testing.T) {
	handler, _ := setupDNSTest()
	tests := []struct {
		qtype uint16
		desc  string
	}{
		{dns.TypeCNAME, "CNAME query"},
		{dns.TypeA, "A query"},
		{dns.TypeAAAA, "AAAA query"},
		{dns.TypeANY, "ANY query"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			resp := queryDNS(handler, "www.test.dev.", tt.qtype)
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(resp.Answer))
			}
			cname, ok := resp.Answer[0].(*dns.CNAME)
			if !ok {
				t.Fatalf("answer is %T, want *dns.CNAME", resp.Answer[0])
			}
			if cname.Target != "example.github.io." {
				t.Errorf("target = %s, want example.github.io.", cname.Target)
			}
		})
	}
}

func TestDNS_CNAME_NoMatchForTXT(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "www.test.dev.", dns.TypeTXT)
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers for TXT on CNAME label, want 0", len(resp.Answer))
	}
}

func TestDNS_OnlyPrivate(t *testing.T) {
	handler, _ := setupDNSTest()
	cfg.OnlyPrivate = true

	// Private IP should resolve
	resp := queryDNS(handler, "127-0-0-1.test.dev.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("private IP: got %d answers, want 1", len(resp.Answer))
	}

	// Public IP should be rejected
	resp = queryDNS(handler, "8-8-8-8.test.dev.", dns.TypeA)
	if len(resp.Answer) != 0 {
		t.Errorf("public IP: got %d answers, want 0", len(resp.Answer))
	}
}

func TestDNS_ACMEChallenge(t *testing.T) {
	handler, ch := setupDNSTest()

	// Root challenge
	ch.Set("", "root-token-123")
	resp := queryDNS(handler, "_acme-challenge.test.dev.", dns.TypeTXT)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("answer is %T, want *dns.TXT", resp.Answer[0])
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "root-token-123" {
		t.Errorf("got %v, want [root-token-123]", txt.Txt)
	}

	// Subdomain challenge
	ch.Set("127-0-0-1", "sub-token-456")
	resp = queryDNS(handler, "_acme-challenge.127-0-0-1.test.dev.", dns.TypeTXT)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	txt = resp.Answer[0].(*dns.TXT)
	if len(txt.Txt) != 1 || txt.Txt[0] != "sub-token-456" {
		t.Errorf("got %v, want [sub-token-456]", txt.Txt)
	}
}

func TestDNS_DefaultWWW(t *testing.T) {
	// When DomainIP is set and no explicit CNAME for www, www should resolve to DomainIP
	handler, _ := setupDNSTest()
	// Remove the explicit www CNAME to test default behavior
	delete(cfg.CNAME, "www")

	t.Run("A record", func(t *testing.T) {
		resp := queryDNS(handler, "www.test.dev.", dns.TypeA)
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
		}
		if a.A.String() != "1.2.3.4" {
			t.Errorf("got %s, want 1.2.3.4", a.A.String())
		}
	})

	t.Run("ANY record", func(t *testing.T) {
		resp := queryDNS(handler, "www.test.dev.", dns.TypeANY)
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(resp.Answer))
		}
		if _, ok := resp.Answer[0].(*dns.A); !ok {
			t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
		}
	})

	t.Run("AAAA with IPv6 DomainIP", func(t *testing.T) {
		cfg.DomainIP = net.ParseIP("2001:db8::1")
		resp := queryDNS(handler, "www.test.dev.", dns.TypeAAAA)
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(resp.Answer))
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("answer is %T, want *dns.AAAA", resp.Answer[0])
		}
		want := net.ParseIP("2001:db8::1")
		if !aaaa.AAAA.Equal(want) {
			t.Errorf("got %s, want %s", aaaa.AAAA, want)
		}
	})

	t.Run("no DomainIP means no www default", func(t *testing.T) {
		cfg.DomainIP = nil
		resp := queryDNS(handler, "www.test.dev.", dns.TypeA)
		if len(resp.Answer) != 0 {
			t.Errorf("got %d answers, want 0 when DomainIP is nil", len(resp.Answer))
		}
	})
}

func TestDNS_ExplicitCNAMEOverridesDefaultWWW(t *testing.T) {
	// When explicit CNAME is set for www, it should take precedence over default DomainIP
	handler, _ := setupDNSTest()
	// setupDNSTest already sets CNAME["www"] = "example.github.io."

	resp := queryDNS(handler, "www.test.dev.", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	cname, ok := resp.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("answer is %T, want *dns.CNAME (explicit CNAME should win)", resp.Answer[0])
	}
	if cname.Target != "example.github.io." {
		t.Errorf("target = %s, want example.github.io.", cname.Target)
	}
}

func TestDNS_OutOfZone(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "other.com.", dns.TypeA)
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers for out-of-zone query, want 0", len(resp.Answer))
	}
}

func TestDNS_UnknownSubdomain(t *testing.T) {
	handler, _ := setupDNSTest()
	resp := queryDNS(handler, "not-an-ip.test.dev.", dns.TypeA)
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers for unknown subdomain, want 0", len(resp.Answer))
	}
}
