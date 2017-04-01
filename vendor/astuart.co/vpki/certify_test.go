package vpki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

type testWriter struct {
	Path string
	Data map[string]interface{}

	t *testing.T

	Res *api.Secret
	Err error
	k   *rsa.PrivateKey
	ca  *x509.Certificate
}

func certFromK(k *rsa.PrivateKey) *x509.Certificate {
	marshaledKey, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		log.Fatal(err)
	}
	subjKeyID := sha1.Sum(marshaledKey)
	sub := pkix.Name{
		CommonName:   "private.ca.localhost",
		Organization: []string{"localhost"},
	}

	// Stole basic template from a combo of Vault code (cert_utils.go) and here:
	// https://golang.org/src/crypto/tls/generate_cert.go
	ctpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               sub,
		SubjectKeyId:          subjKeyID[:],
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	bs, err := x509.CreateCertificate(rand.Reader, ctpl, ctpl, k.Public(), k)
	if err != nil {
		log.Fatal(err)
	}

	crt, err := x509.ParseCertificate(bs)
	if err != nil {
		log.Fatal(err)
	}

	return crt
}

func (tw *testWriter) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	tw.Path, tw.Data = path, data

	if tw.k == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tw.t.Fatalf("error generating our key")
			return nil, fmt.Errorf("error generating our key")
		}
		tw.k = k
		tw.ca = certFromK(k)
	}

	// Copying from vault internals
	csrString := data["csr"].(string)
	if csrString == "" {
		tw.t.Log("Error getting csr")
		return nil, fmt.Errorf("empty csr")
	}

	pemBytes := []byte(csrString)
	pemBlock, pemBytes := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("csr contains no data")
	}
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate request could not be parsed")
	}

	marshaledKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %s", err)
	}
	subjKeyID := sha1.Sum(marshaledKey)

	subject := pkix.Name{
		CommonName: data["common_name"].(string),
	}

	certTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            subject,
		SubjectKeyId:       subjKeyID[:],
		NotBefore:          time.Now().Add(-30 * time.Second),
		NotAfter:           time.Now().Add(5 * time.Minute),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	bs, err := x509.CreateCertificate(rand.Reader, certTemplate, tw.ca, csr.PublicKey, tw.k)

	tw.Res = &api.Secret{
		Data: map[string]interface{}{
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bs})),
		},
	}

	return tw.Res, tw.Err
}

var tw = &testWriter{}

func TestCertify(t *testing.T) {
	asrt := assert.New(t)
	tw.t = t
	cli := Client{
		Mount:    "foo",
		Role:     "bar",
		sw:       tw,
		Strength: 2048,
		TTL:      time.Second,
	}

	crt, err := cli.Cert("foo.localhost")
	if err != nil {
		t.Fatalf("Error certifying: %v", err)
	}

	if crt.Leaf == nil {
		t.Fatalf("Nil certificate leaf")
	}

	if crt.Leaf.Subject.CommonName != "foo.localhost" {
		t.Errorf("Wrong subject name returned.")
	}

	asrt.Equal("foo/sign-verbatim", tw.Path)
	asrt.Equal("foo.localhost", tw.Data["common_name"])
}
