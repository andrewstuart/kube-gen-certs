package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go.astuart.co/vpki"

	"net/http"
	_ "net/http/pprof"

	"k8s.io/kubernetes/pkg/api"
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
)

func init() {
	flag.Parse()
}

type certer struct {
	c   vpki.Certifier
	api *unversioned.Client
}

func main() {
	var config *restclient.Config

	ttlD, err := time.ParseDuration(*ttl)
	if err != nil {
		log.Fatal(err)
	}

	// PPROF server
	go http.ListenAndServe(":8080", nil)

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

	watching := false

	for {
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
					log.Println(err)
				}
			}

			//LF
			fmt.Println()
		}

		if !watching {
			watching = true
			go ctr.watchIng()
		}
		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttlD)))
	}
}
