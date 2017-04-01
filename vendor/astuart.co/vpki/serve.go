package vpki

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	day  = 24 * time.Hour
	year = 365 * day

	//DefaultTTL is the default TTL the library will request for certificates
	DefaultTTL = day
	//DefaultStrength is the default strength of RSA keys generated
	DefaultStrength = 2048

	promVPKICertError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vpki_cert_error",
		Help: "vpki encountered an error obtaining a certificate",
	}, []string{"server_name"})
)

func init() {
	prometheus.MustRegister(promVPKICertError)
}

// SNICertifier abstracts the basic GetCertificate method used in TLSOpts, and
// also implemented by libraries like rsc.io/letsencrypt
type SNICertifier interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// ListenAndServeTLS mostly mirrors the http.ListenAndServeTLS API, but
// generates the certificates for the server automatically via vault, with a
// short TTL. The function only needs an additional Certifier parameter which
// can generate signed certificates in order to work properly.
func ListenAndServeTLS(addr string, handler http.Handler, crt Certifier) error {
	certs := newCertCache(crt)

	if handler == nil {
		handler = http.DefaultServeMux
	}

	s := http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: func(h *tls.ClientHelloInfo) (c *tls.Certificate, err error) {
				defer func() {
					if err != nil {
						promVPKICertError.With(prometheus.Labels{"server_name": h.ServerName}).Inc()
					}
				}()

				if h.ServerName == "" {
					err = fmt.Errorf("Cannot generate certs without TLS SNI (no server name was indicated)")
					return
				}

				if crt, ok := crt.(SNICertifier); ok {
					c, err = crt.GetCertificate(h)
					return
				}

				c, err = certs.get(h.ServerName)
				return
			},
		},
	}

	return s.ListenAndServeTLS("", "")
}
