package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

type certKeyType int

const (
	keyTypeECDSA certKeyType = iota
	keyTypeRSA
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

// CertFiles returns paths to the current ECDSA certificate and key.
func (m *CertManager) EcdsaCertFiles() (cert, key string) {
	return m.certFile, m.keyFile
}

// RsaCertFiles returns paths to the current RSA certificate and key.
func (m *CertManager) RsaCertFiles() (cert, key string) {
	dir := filepath.Dir(m.certFile)
	return filepath.Join(dir, "fullchain-rsa.pem"), filepath.Join(dir, "privkey-rsa.pem")
}

// SubdomainEcdsaCertFiles returns paths to a subdomain ECDSA certificate and key.
func (m *CertManager) SubdomainEcdsaCertFiles(label string) (cert, key string) {
	dir := filepath.Join(cfg.CertDir, "sub", label)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

// SubdomainRsaCertFiles returns paths to a subdomain RSA certificate and key.
func (m *CertManager) SubdomainRsaCertFiles(label string) (cert, key string) {
	dir := filepath.Join(cfg.CertDir, "sub", label)
	return filepath.Join(dir, "fullchain-rsa.pem"), filepath.Join(dir, "privkey-rsa.pem")
}

// HasEcdsaCertificate checks if certificate files exist.
func (m *CertManager) HasEcdsaCertificate() bool {
	_, err1 := os.Stat(m.certFile)
	_, err2 := os.Stat(m.keyFile)
	return err1 == nil && err2 == nil
}

// NeedsEcdsaRenewal checks if the certificate expires within 30 days.
func (m *CertManager) NeedsEcdsaRenewal() bool {
	if !m.HasEcdsaCertificate() {
		return true
	}
	return needsRenewal(m.certFile)
}

// HasRsaCertificate checks if RSA certificate files exist.
func (m *CertManager) HasRsaCertificate() bool {
	rsaCertFile, rsaKeyFile := m.RsaCertFiles()
	_, err1 := os.Stat(rsaCertFile)
	_, err2 := os.Stat(rsaKeyFile)
	return err1 == nil && err2 == nil
}

// NeedsRsaRenewal checks if the RSA certificate expires within 30 days.
func (m *CertManager) NeedsRsaRenewal() bool {
	if !m.HasRsaCertificate() {
		return true
	}
	rsaCertFile, _ := m.RsaCertFiles()
	return needsRenewal(rsaCertFile)
}

// EnsureEcdsaCertificate requests a certificate if needed.
func (m *CertManager) EnsureEcdsaCertificate() error {
	if !m.NeedsEcdsaRenewal() {
		log.Printf("[acme] certificate is valid, no renewal needed")
		return nil
	}

	log.Printf("[acme] requesting wildcard certificate...")
	return m.requestEcdsaCertificate()
}

// EnsureRsaCertificate requests an RSA certificate if needed.
func (m *CertManager) EnsureRsaCertificate() error {
	if !m.NeedsRsaRenewal() {
		log.Printf("[acme] RSA certificate is valid, no renewal needed")
		return nil
	}

	log.Printf("[acme] requesting RSA wildcard certificate...")
	return m.requestRsaCertificate()
}

// AutoRenew checks certificate expiry periodically and renews.
func (m *CertManager) AutoRenew() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Root ECDSA cert
		if m.NeedsEcdsaRenewal() {
			log.Printf("[acme] certificate needs renewal, requesting...")
			if err := m.requestEcdsaCertificate(); err != nil {
				log.Printf("[acme] renewal failed: %v (will retry)", err)
			}
		}

		// Root RSA cert
		if m.NeedsRsaRenewal() {
			log.Printf("[acme] RSA certificate needs renewal, requesting...")
			if err := m.requestRsaCertificate(); err != nil {
				log.Printf("[acme] RSA renewal failed: %v (will retry)", err)
			}
		}

		// Subdomain certs
		for _, label := range m.listSubdomainLabels() {
			certFile, _ := m.SubdomainEcdsaCertFiles(label)
			if needsRenewal(certFile) {
				log.Printf("[acme] subdomain cert %s needs renewal, requesting...", label)
				if err := m.requestSubdomainEcdsaCert(label); err != nil {
					log.Printf("[acme] subdomain %s renewal failed: %v (will retry)", label, err)
				}
			}
			rsaCertFile, _ := m.SubdomainRsaCertFiles(label)
			if needsRenewal(rsaCertFile) {
				log.Printf("[acme] subdomain RSA cert %s needs renewal, requesting...", label)
				if err := m.requestSubdomainRsaCert(label); err != nil {
					log.Printf("[acme] subdomain %s RSA renewal failed: %v (will retry)", label, err)
				}
			}
		}
	}
}

func (m *CertManager) requestEcdsaCertificate() error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	return m.issueCertificate(
		[]string{domain, "*." + domain},
		m.certFile, m.keyFile, "", keyTypeECDSA,
	)
}

func (m *CertManager) requestRsaCertificate() error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	certFile, keyFile := m.RsaCertFiles()
	return m.issueCertificate(
		[]string{domain, "*." + domain},
		certFile, keyFile, "", keyTypeRSA,
	)
}

func (m *CertManager) requestSubdomainEcdsaCert(label string) error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	subDomain := label + "." + domain
	certFile, keyFile := m.SubdomainEcdsaCertFiles(label)

	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	return m.issueCertificate(
		[]string{subDomain, "*." + subDomain},
		certFile, keyFile, label, keyTypeECDSA,
	)
}

func (m *CertManager) requestSubdomainRsaCert(label string) error {
	domain := strings.TrimSuffix(cfg.Domain, ".")
	subDomain := label + "." + domain
	certFile, keyFile := m.SubdomainRsaCertFiles(label)

	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	return m.issueCertificate(
		[]string{subDomain, "*." + subDomain},
		certFile, keyFile, label, keyTypeRSA,
	)
}

// RequestSubdomainEcdsaCert requests a wildcard ECDSA certificate for *.{label}.{domain}.
// The label must be a valid IP pattern (e.g., "127-0-0-1").
func (m *CertManager) RequestSubdomainEcdsaCert(label string) error {
	if extractIP(label) == nil {
		return fmt.Errorf("invalid IP label: %s", label)
	}

	if !cfg.CertSubs[label] {
		return fmt.Errorf("label not allowed: %s", label)
	}

	certFile, _ := m.SubdomainEcdsaCertFiles(label)
	if !needsRenewal(certFile) {
		log.Printf("[acme] subdomain cert %s is valid, no renewal needed", label)
		return nil
	}

	log.Printf("[acme] requesting wildcard certificate for *.%s.%s...", label, strings.TrimSuffix(cfg.Domain, "."))
	return m.requestSubdomainEcdsaCert(label)
}

// RequestSubdomainRsaCert requests a wildcard RSA certificate for *.{label}.{domain}.
// The label must be a valid IP pattern (e.g., "127-0-0-1").
func (m *CertManager) RequestSubdomainRsaCert(label string) error {
	if extractIP(label) == nil {
		return fmt.Errorf("invalid IP label: %s", label)
	}

	if !cfg.CertSubs[label] {
		return fmt.Errorf("label not allowed: %s", label)
	}

	certFile, _ := m.SubdomainRsaCertFiles(label)
	if !needsRenewal(certFile) {
		log.Printf("[acme] subdomain RSA cert %s is valid, no renewal needed", label)
		return nil
	}

	log.Printf("[acme] requesting RSA wildcard certificate for *.%s.%s...", label, strings.TrimSuffix(cfg.Domain, "."))
	return m.requestSubdomainRsaCert(label)
}

func (m *CertManager) issueCertificate(domains []string, certFile, keyFile, challengeLabel string, kt certKeyType) error {
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
	var certKey crypto.Signer
	var keyPEM []byte
	if kt == keyTypeRSA {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate RSA cert key: %w", err)
		}
		keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
		certKey = rsaKey
	} else {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate cert key: %w", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return fmt.Errorf("marshal key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		certKey = ecKey
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
func (m *CertManager) EcdsaCertInfo() (map[string]any, error) {
	return certInfoFromFile(m.certFile)
}

// CertInfoJSON returns certificate metadata as JSON bytes.
func (m *CertManager) EcdsaCertInfoJSON() ([]byte, error) {
	info, err := m.EcdsaCertInfo()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}

// SubdomainEcdsaCertInfo returns metadata about a subdomain ECDSA certificate.
func (m *CertManager) SubdomainEcdsaCertInfo(label string) (map[string]any, error) {
	certFile, _ := m.SubdomainEcdsaCertFiles(label)
	return certInfoFromFile(certFile)
}

// SubdomainEcdsaCertInfoJSON returns subdomain ECDSA certificate metadata as JSON bytes.
func (m *CertManager) SubdomainEcdsaCertInfoJSON(label string) ([]byte, error) {
	info, err := m.SubdomainEcdsaCertInfo(label)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}

// RsaCertInfo returns metadata about the current RSA certificate.
func (m *CertManager) RsaCertInfo() (map[string]any, error) {
	certFile, _ := m.RsaCertFiles()
	return certInfoFromFile(certFile)
}

// RsaCertInfoJSON returns RSA certificate metadata as JSON bytes.
func (m *CertManager) RsaCertInfoJSON() ([]byte, error) {
	info, err := m.RsaCertInfo()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}

// SubdomainRsaCertInfo returns metadata about a subdomain RSA certificate.
func (m *CertManager) SubdomainRsaCertInfo(label string) (map[string]any, error) {
	certFile, _ := m.SubdomainRsaCertFiles(label)
	return certInfoFromFile(certFile)
}

// SubdomainRsaCertInfoJSON returns subdomain RSA certificate metadata as JSON bytes.
func (m *CertManager) SubdomainRsaCertInfoJSON(label string) ([]byte, error) {
	info, err := m.SubdomainRsaCertInfo(label)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(info, "", "  ")
}
