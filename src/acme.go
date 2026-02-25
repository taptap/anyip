package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// ChallengeStore holds ACME DNS-01 challenge tokens, keyed by label.
// Label "" is the root domain; "127-0-0-1" is for *.127-0-0-1.anyip.dev, etc.
type ChallengeStore struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{tokens: make(map[string]string)}
}

func (c *ChallengeStore) Set(label, token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[label] = token
}

func (c *ChallengeStore) Get(label string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tokens[label]
}

func (c *ChallengeStore) Clear(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, label)
}

// CertManager handles ACME certificate issuance and renewal.
type CertManager struct {
	challenges *ChallengeStore
	certFile   string
	keyFile    string
	accountKey string
	acmeMu     sync.Mutex
}

func NewCertManager(challenges *ChallengeStore) *CertManager {
	return &CertManager{
		challenges: challenges,
		certFile:   filepath.Join(cfg.CertDir, "fullchain.pem"),
		keyFile:    filepath.Join(cfg.CertDir, "privkey.pem"),
		accountKey: filepath.Join(cfg.CertDir, "account.key"),
	}
}

// CertFiles returns paths to the current certificate and key.
func (m *CertManager) CertFiles() (cert, key string) {
	return m.certFile, m.keyFile
}

// SubdomainCertFiles returns paths to a subdomain certificate and key.
func (m *CertManager) SubdomainCertFiles(label string) (cert, key string) {
	dir := filepath.Join(cfg.CertDir, "sub", label)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// HasCertificate checks if certificate files exist.
func (m *CertManager) HasCertificate() bool {
	_, err1 := os.Stat(m.certFile)
	_, err2 := os.Stat(m.keyFile)
	return err1 == nil && err2 == nil
}

// NeedsRenewal checks if the certificate expires within 30 days.
func (m *CertManager) NeedsRenewal() bool {
	if !m.HasCertificate() {
		return true
	}
	return needsRenewal(m.certFile)
}

// EnsureCertificate requests a certificate if needed.
func (m *CertManager) EnsureCertificate() error {
	if !m.NeedsRenewal() {
		log.Printf("[acme] certificate is valid, no renewal needed")
		return nil
	}

	log.Printf("[acme] requesting wildcard certificate...")
	return m.requestCertificate()
}

// AutoRenew checks certificate expiry periodically and renews.
func (m *CertManager) AutoRenew() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Root cert
		if m.NeedsRenewal() {
			log.Printf("[acme] certificate needs renewal, requesting...")
			if err := m.requestCertificate(); err != nil {
				log.Printf("[acme] renewal failed: %v (will retry)", err)
			}
		}

		// Subdomain certs
		for _, label := range m.listSubdomainLabels() {
			certFile, _ := m.SubdomainCertFiles(label)
			if needsRenewal(certFile) {
				log.Printf("[acme] subdomain cert %s needs renewal, requesting...", label)
				if err := m.requestSubdomainCert(label); err != nil {
					log.Printf("[acme] subdomain %s renewal failed: %v (will retry)", label, err)
				}
			}
		}
	}
}

func (m *CertManager) requestCertificate() error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	return m.issueCertificate(
		[]string{domain, "*." + domain},
		m.certFile, m.keyFile, "",
	)
}

func (m *CertManager) requestSubdomainCert(label string) error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	subDomain := label + "." + domain
	certFile, keyFile := m.SubdomainCertFiles(label)

	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	return m.issueCertificate(
		[]string{subDomain, "*." + subDomain},
		certFile, keyFile, label,
	)
}

// RequestSubdomainCert requests a wildcard certificate for *.{label}.{domain}.
// The label must be a valid IP pattern (e.g., "127-0-0-1").
func (m *CertManager) RequestSubdomainCert(label string) error {
	if extractIP(label) == nil {
		return fmt.Errorf("invalid IP label: %s", label)
	}

	if !cfg.CertSubs[label] {
		return fmt.Errorf("label not allowed: %s", label)
	}

	certFile, _ := m.SubdomainCertFiles(label)
	if !needsRenewal(certFile) {
		log.Printf("[acme] subdomain cert %s is valid, no renewal needed", label)
		return nil
	}

	log.Printf("[acme] requesting wildcard certificate for *.%s.%s...", label, strings.TrimSuffix(cfg.Domain, "."))
	return m.requestSubdomainCert(label)
}

func (m *CertManager) issueCertificate(domains []string, certFile, keyFile, challengeLabel string) error {
	m.acmeMu.Lock()
	defer m.acmeMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Load or create account key
	accountKey, err := m.loadOrCreateAccountKey()
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}

	// ACME directory
	directoryURL := acme.LetsEncryptURL
	if cfg.ACMEStaging {
		directoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
	}

	// Register account (ignore "already exists" error)
	acct := &acme.Account{Contact: []string{"mailto:" + cfg.ACMEEmail}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("register: %w", err)
		}
	}

	// Create order
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	// Fulfill DNS-01 challenges
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("get authz: %w", err)
		}

		if authz.Status == acme.StatusValid {
			continue
		}

		for _, ch := range authz.Challenges {
			if ch.Type != "dns-01" {
				continue
			}

			// Compute the DNS-01 response value
			val, err := client.DNS01ChallengeRecord(ch.Token)
			if err != nil {
				return fmt.Errorf("dns01 record: %w", err)
			}

			// Set it in our DNS handler
			log.Printf("[acme] setting DNS-01 challenge for %s", authz.Identifier.Value)
			m.challenges.Set(challengeLabel, val)

			// Wait a moment for DNS propagation
			time.Sleep(2 * time.Second)

			// Accept the challenge
			if _, err := client.Accept(ctx, ch); err != nil {
				m.challenges.Clear(challengeLabel)
				return fmt.Errorf("accept challenge: %w", err)
			}

			// Wait for validation
			if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
				m.challenges.Clear(challengeLabel)
				return fmt.Errorf("wait authz: %w", err)
			}

			m.challenges.Clear(challengeLabel)
			break
		}
	}

	// Generate certificate key
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cert key: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	// Finalize order
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	// Write certificate chain
	var certPEM []byte
	for _, d := range der {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write private key
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	log.Printf("[acme] certificate issued for %s", strings.Join(domains, ", "))
	return nil
}

func (m *CertManager) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(m.accountKey)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}

	// Generate new account key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(m.accountKey, pemData, 0600); err != nil {
		return nil, err
	}

	log.Printf("[acme] created new account key: %s", m.accountKey)
	return key, nil
}

// listSubdomainLabels returns all subdomain labels that have cert directories.
func (m *CertManager) listSubdomainLabels() []string {
	subDir := filepath.Join(cfg.CertDir, "sub")
	entries, err := os.ReadDir(subDir)
	if err != nil {
		return nil
	}
	var labels []string
	for _, e := range entries {
		if e.IsDir() {
			labels = append(labels, e.Name())
		}
	}
	return labels
}

// needsRenewal checks if a certificate file expires within 30 days.
func needsRenewal(certFile string) bool {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return true
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}

	return time.Until(cert.NotAfter) < 30*24*time.Hour
}

// certInfoFromFile extracts metadata from a certificate file.
func certInfoFromFile(certFile string) (map[string]any, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"domains":   cert.DNSNames,
		"notBefore": cert.NotBefore,
		"notAfter":  cert.NotAfter,
		"issuer":    cert.Issuer.CommonName,
		"serial":    cert.SerialNumber.String(),
	}, nil
}

// CertInfo returns metadata about the current certificate.
func (m *CertManager) CertInfo() (map[string]any, error) {
	return certInfoFromFile(m.certFile)
}

// CertInfoJSON returns certificate metadata as JSON bytes.
func (m *CertManager) CertInfoJSON() ([]byte, error) {
	info, err := m.CertInfo()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}

// SubdomainCertInfo returns metadata about a subdomain certificate.
func (m *CertManager) SubdomainCertInfo(label string) (map[string]any, error) {
	certFile, _ := m.SubdomainCertFiles(label)
	return certInfoFromFile(certFile)
}

// SubdomainCertInfoJSON returns subdomain certificate metadata as JSON bytes.
func (m *CertManager) SubdomainCertInfoJSON(label string) ([]byte, error) {
	info, err := m.SubdomainCertInfo(label)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}
