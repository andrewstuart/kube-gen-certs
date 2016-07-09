package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"astuart.co/vpki"
)

func getVaultCertifier(ttlD time.Duration) *vpki.Client {
	vc := &vpki.Client{
		Addr:     os.Getenv("VAULT_ADDR"),
		Email:    "andrew.stuart2@gmail.com",
		Mount:    "pki",
		Role:     "astuart",
		Strength: 2048,
		TTL:      ttlD,
	}

	ca := os.Getenv("ROOT_CA")
	if ca != "" {
		cp := x509.NewCertPool()
		cp.AppendCertsFromPEM([]byte(ca))
		vc.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: cp},
			},
		}
	}

	switch {
	case os.Getenv("VAULT_TOKEN") != "":
		vc.SetToken(os.Getenv("VAULT_TOKEN"))
	default:
		bs, err := ioutil.ReadFile("~/.vault-token")
		if err != nil {
			log.Fatal(err)
		}
		vc.SetToken(string(bs))
	}

	return vc
}
