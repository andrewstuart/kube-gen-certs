package vpki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	tw.t = t
	c := &Client{
		Mount:    "plop",
		Role:     "foo",
		Strength: 2048,
		TTL:      time.Hour,

		sw: tw,
	}

	m := http.NewServeMux()

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello world")
	})

	c.Cert("foo")

	go func() {
		err := ListenAndServeTLS(":12346", m, c)
		if err != nil {
			t.Fatalf("Error serving: %v", err)
		}
	}()

	certP := x509.NewCertPool()
	certP.AddCert(tw.ca)

	tlsCfg := &tls.Config{
		RootCAs: certP,
	}

	cli := http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	res, err := cli.Get("https://localhost:12346/")
	if err != nil {
		t.Fatalf("Error getting localhost:12346: %v", err)
	}

	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	if string(bs) != "hello world" {
		t.Errorf("Wrong response body: %v", string(bs))
	}
}
