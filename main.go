package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"astuart.co/vpki"

	"net/http"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned"
)

const (
	backendLE    = "letsencrypt"
	backendVault = "vault"
)

var (
	inCluster = flag.Bool("incluster", false, "the client is running inside a kuberenetes cluster")
	ttl       = flag.String("ttl", "240h", "the time to live for certificates")
	forceTLS  = flag.Bool("forcetls", false, "force all ingresses to use TLS")
	backend   = flag.String("backend", "letsencrypt", fmt.Sprintf("the backend to use for certificates. One of: %s, %s", backendLE, backendVault))

	certGen = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_generated",
		Help: "The number of certificates kubernetes has generated",
	}, []string{"registered_domain", "ttl"})

	certErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cert_errors",
		Help: "The number of certificate requests that have resulted in errors",
	}, []string{"ingress", "namespace", "ttl"})
)

func certErrInc(ing *extensions.Ingress) {
	certErrors.With(prometheus.Labels{
		"ingress":   ing.Name,
		"namespace": ing.Namespace,
		"ttl":       *ttl,
	}).Inc()
}

func init() {
	prometheus.MustRegisterAll(certGen, certErrors)
	flag.Parse()
}

type certer struct {
	c   vpki.Certifier
	api *unversioned.Client

	hf func(*extensions.Ingress) error
}

func main() {
	var config *restclient.Config

	ttlD, err := time.ParseDuration(*ttl)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/metrics", prometheus.Handler())

	// PPROF server
	go http.ListenAndServe(":8080", prometheus.InstrumentHandler("default", http.DefaultServeMux))

	log.Println(*ttl, *inCluster)

	if *inCluster {
		var err error
		config, err = restclient.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		config = &restclient.Config{
			Host: os.Getenv("KUBE_API_HOST"),
		}
	}

	var crt vpki.Certifier

	switch *backend {
	case backendLE:
		crt = getLECertifier()
		//LE TTL is 90 days
		ttlD = 90 * 24 * time.Hour
	case backendVault:
		crt = getVaultCertifier(ttlD)
	}

	cli, err := unversioned.New(config)
	if err != nil {
		log.Fatal(err)
	}

	ctr := &certer{c: crt, api: cli}

	// Start watching, which will also do the initial issuance.
	go ctr.watchIng()

	for {
		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttlD)))

		ns, err := cli.Namespaces().List(api.ListOptions{})
		if err != nil {
			log.Fatal(err)
		}

		for _, n := range ns.Items {
			fmt.Println("Namespace", n.Name)
			i := cli.Extensions().Ingress(n.Name)

			li, err := i.List(api.ListOptions{})
			if err != nil {
				log.Fatal(err)
			}

			for _, ing := range li.Items {
				_, err := ctr.addTLSSecrets(&ing)
				if err != nil {
					certErrInc(&ing)
					log.Println("Error adding TlS secret", err)
				}
			}

			//LF
			fmt.Println()
		}

	}
}
