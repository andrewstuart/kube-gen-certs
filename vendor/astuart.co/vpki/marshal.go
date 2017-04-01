package vpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RawCertifier is an interface implemented by types that can give back a RawPair
type RawCertifier interface {
	RawCert(string) (*RawPair, error)
}

// RawCert is a more-generic function that can take any certifier and return
// the PEM-encoded bytes for a requested common_name.
func RawCert(c Certifier, cn string) (*RawPair, error) {
	if c, ok := c.(RawCertifier); ok {
		// Short path for Vault Client, where we know the RawCert can be obtained
		// directly
		if c == nil {
			return nil, fmt.Errorf("nil Client passed as certifier")
		}
		return c.RawCert(cn)
	}

	crt, err := c.Cert(cn)
	if err != nil {
		return nil, err
	}

	crts, err := x509.ParseCertificates(bytes.Join(crt.Certificate, []byte{}))
	if err != nil {
		return nil, err
	}

	pubBs := []byte{}
	for _, crt := range crts {
		pubBs = append(pubBs, pem.EncodeToMemory(&pem.Block{
			Bytes: crt.Raw,
			Type:  "CERTIFICATE",
		})...)
	}

	r := RawPair{Public: pubBs}

	var privBs []byte
	var privT string

	switch k := crt.PrivateKey.(type) {
	case *rsa.PrivateKey:
		privT, privBs = "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		privT = "EC PRIVATE KEY"
		privBs, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Unrecognized private key type")
	}

	r.Private = pem.EncodeToMemory(&pem.Block{Type: privT, Bytes: privBs})

	return &r, nil
}
