package vpki

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// SignCSR takes an CertificateRequest template and ttl, and returns a
// tls.Certificate with a pre-parsed leaf, or an error.
func (c *Client) SignCSR(csr *x509.CertificateRequest, k *rsa.PrivateKey, ttl time.Duration) (*tls.Certificate, error) {
	raw, err := c.RawSignCSR(csr, k, ttl)
	if err != nil {
		return nil, err
	}

	return parseRawPair(raw)
}

func parseRawPair(raw *RawPair) (*tls.Certificate, error) {
	crt, err := tls.X509KeyPair(raw.Public, raw.Private)
	if err != nil {
		return nil, fmt.Errorf("x509 keypair error: %v", err)
	}

	crt.Leaf, err = x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &crt, nil
}
