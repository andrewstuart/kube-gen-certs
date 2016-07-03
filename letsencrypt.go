package main

import (
	"log"
	"os"

	"rsc.io/letsencrypt"
)

func getLECertifier() *letsencrypt.Manager {
	m := &letsencrypt.Manager{}
	m.CacheFile("le.cache")
	err := m.Register(os.Getenv("EMAIL"), nil)
	if err != nil {
		log.Fatal(err)
	}

	return m
}
