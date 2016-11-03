package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"astuart.co/vpki"
)

type SelfSigner struct{ ttl time.Duration }

//2^128 as largest serial
var serialLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func (s *SelfSigner) RawCert(cn string) (*vpki.RawPair, error) {
	n := pkix.Name{CommonName: cn}

	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	c := &x509.Certificate{
		Subject:      n,
		DNSNames:     []string{cn},
		SerialNumber: serial,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(s.ttl),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	p, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	crt, err := x509.CreateCertificate(rand.Reader, c, c, p.Public(), p)
	if err != nil {
		return nil, err
	}

	privBlock := &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(p),
		Type:  "RSA PRIVATE KEY",
	}

	pubBlock := &pem.Block{
		Bytes: crt,
		Type:  "CERTIFICATE",
	}

	return &vpki.RawPair{
		Public:  pem.EncodeToMemory(pubBlock),
		Private: pem.EncodeToMemory(privBlock),
	}, nil
}
