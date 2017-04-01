package vpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

const (
	csrName = "CERTIFICATE REQUEST"
)

// ValidationError is a structured type that contains additional error context.
type ValidationError struct {
	Domain   string
	Original error
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("Error acquiring cert for %s: %s", ve.Domain, ve.Original)
}

// Certifier abstracts any object that can provide signed certificates
// (hopefully valid for their use case). Concrete implementations ought to
// provide their own ways to configure TTL, key strength, etc. The default
// provided implementation is vpki.Client.
type Certifier interface {
	Cert(cn string) (*tls.Certificate, error)
}

// RawMarshaler abstracts a RawCertifier and offers to return parsed
// tls.Certificates
type RawMarshaler struct {
	RawCertifier
}

// Cert uses the original interface's RawCert method and returns a
// tls.Certificate
func (r *RawMarshaler) Cert(cn string) (*tls.Certificate, error) {
	pair, err := r.RawCertifier.RawCert(cn)
	if err != nil {
		return nil, err
	}

	return parseRawPair(pair)
}

// Cert takes a server CommonName and retruns a tls.Certificate with a
// pre-parsed Leaf, or an error. The strength and ttl for the CSR are
// determined by the Client fields of the same names.
func (c *Client) Cert(cn string) (*tls.Certificate, error) {
	csr, k, err := c.getCSR(cn)
	if err != nil {
		return nil, err
	}
	return c.SignCSR(csr, k, c.TTL)
}

// GenCert takes a CertificateRequest template, generates a key, obtains a
// signed certificate, and returns the lot
func (c *Client) GenCert(template *x509.CertificateRequest) (*RawPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, c.Strength)
	if err != nil {
		return nil, err
	}

	return c.RawSignCSR(template, k, c.TTL)
}

func (c *Client) getCSR(cn string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, c.Strength)
	if err != nil {
		return nil, nil, err
	}

	return &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		EmailAddresses: []string{c.Email},
	}, k, nil
}
