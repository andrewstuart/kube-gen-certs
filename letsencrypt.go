package main

import (
	"log"
	"os"

	"astuart.co/vpki"

	"rsc.io/letsencrypt"
)

func getLECertifier() *letsencrypt.Manager {
	m := &letsencrypt.Manager{}
	m.CacheFile("le.cache")
	err := m.Register(os.Getenv("EMAIL"), nil)
	if err != nil {
		log.Fatal(err)
	}

	//TODO set an ingress update handler??
	//TODO create a service to route to us

	go func() {
		log.Fatal(vpki.ListenAndServeTLS(":8443", nil, m))
	}()

	return m
}
