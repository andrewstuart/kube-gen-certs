package vpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/hashicorp/vault/api"
)

// RawPair is a simple explicitly-named pair of byte slices returned by
// the RawPair function.
type RawPair struct {
	Private, Public []byte
}

// RawSignCSR takes a certificate request template, private keye, and ttl, and
// returns the private/public keypair, unparsed, for any applications which may
// need to consume the certificates directly in their PEM form. The RawPair
// struct is used to help prevent transposition errors by explicitly naming the
// public/private pairs rather than returning two byte slices.
func (c *Client) RawSignCSR(csr *x509.CertificateRequest, k *rsa.PrivateKey, ttl time.Duration) (*RawPair, error) {
	csrBs, err := x509.CreateCertificateRequest(rand.Reader, csr, k)
	if err != nil {
		return nil, err
	}

	pubBs, err := c.rawCSR(csrBs, csr.Subject.CommonName, ttl)
	if err != nil {
		return nil, err
	}

	return &RawPair{Public: pubBs, Private: pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})}, nil
}

// RawCert is a very high-level method used to obtain the raw certificate data.
func (c *Client) RawCert(cn string) (*RawPair, error) {
	csr, k, err := c.getCSR(cn)
	if err != nil {
		return nil, err
	}
	return c.RawSignCSR(csr, k, c.TTL)
}

func (c *Client) rawCSR(csr []byte, cn string, ttl time.Duration) ([]byte, error) {
	pemB := &pem.Block{
		Bytes: csr,
		Type:  csrName,
	}

	return c.RawSignCSRBytes(pem.EncodeToMemory(pemB), cn, ttl)
}

func (c *Client) write(path string, data map[string]interface{}) (*api.Secret, error) {
	return c.sw.Write(c.Mount+"/"+path, data)
}

//RawSignCSRBytes takes the bytes of a Certificate Signing Request, the CN and
//the ttl, and returns raw bytes of the signed certificate bundle.
func (c *Client) RawSignCSRBytes(csr []byte, cn string, ttl time.Duration) ([]byte, error) {

	data := map[string]interface{}{
		"csr":         string(csr),
		"common_name": cn,
		"format":      "pem_bundle",
		"ttl":         ttl.String(),
	}

	if c.sw == nil {
		c.init()
	}

	secret, err := c.write("sign-verbatim", data)
	if err != nil {
		return nil, err
	}

	return []byte(secret.Data["certificate"].(string)), nil
}
