package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertManager manages CA and host certificates
type CertManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caCertPath string
	caKeyPath  string
}

// NewCertManager creates a new certificate manager
func NewCertManager(certDir string) (*CertManager, error) {
	if certDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		certDir = filepath.Join(home, ".chain-gate", "certs")
	}

	// Ensure directory exists
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	caCertPath := filepath.Join(certDir, "ca-cert.pem")
	caKeyPath := filepath.Join(certDir, "ca-key.pem")

	cm := &CertManager{
		caCertPath: caCertPath,
		caKeyPath:  caKeyPath,
	}

	// Try to load existing CA cert
	if err := cm.loadCA(); err != nil {
		// If loading fails, generate new CA
		if err := cm.generateCA(); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	return cm, nil
}

// loadCA loads existing CA certificate and key
func (cm *CertManager) loadCA() error {
	// Load certificate
	certPEM, err := os.ReadFile(cm.caCertPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// Check if certificate is still valid
	now := time.Now()
	if now.Before(caCert.NotBefore) || now.After(caCert.NotAfter) {
		return fmt.Errorf("CA certificate expired or not yet valid")
	}

	// Load private key
	keyPEM, err := os.ReadFile(cm.caKeyPath)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	cm.caCert = caCert
	cm.caKey = caKey

	return nil
}

// generateCA generates a new CA certificate and key
func (cm *CertManager) generateCA() error {
	// Generate private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	caCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Chain Gate CA"},
			CommonName:   "Chain Gate Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	if err := os.WriteFile(cm.caCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Save private key to file
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	if err := os.WriteFile(cm.caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	cm.caCert = caCert
	cm.caKey = caKey

	return nil
}

// GenerateHostCert generates a certificate for a specific host
func (cm *CertManager) GenerateHostCert(host string) (*tls.Certificate, error) {
	// Generate private key for host
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	hostCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Chain Gate"},
			CommonName:   host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour), // Valid for 1 day
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	// Create certificate signed by CA
	hostCertDER, err := x509.CreateCertificate(rand.Reader, hostCertTemplate, cm.caCert, &hostKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %w", err)
	}

	// Create tls.Certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{hostCertDER, cm.caCert.Raw},
		PrivateKey:  hostKey,
	}

	return tlsCert, nil
}

// GetCACertPath returns the path to the CA certificate file
func (cm *CertManager) GetCACertPath() string {
	return cm.caCertPath
}

// GetCACert returns the CA certificate
func (cm *CertManager) GetCACert() *x509.Certificate {
	return cm.caCert
}

// GetCAKey returns the CA private key
func (cm *CertManager) GetCAKey() *rsa.PrivateKey {
	return cm.caKey
}
