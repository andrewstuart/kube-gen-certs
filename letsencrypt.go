package main

import (
	"log"
	"os"

	"go.astuart.co/vpki"

	"rsc.io/letsencrypt"
)

func getLECertifier() *letsencrypt.Manager {
	m := &letsencrypt.Manager{}
	m.CacheFile("le.cache")
	err := m.Register(os.Getenv("EMAIL"), nil)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Fatal(vpki.ListenAndServeTLS(":8443", nil, m))
	}()

	return m
}
