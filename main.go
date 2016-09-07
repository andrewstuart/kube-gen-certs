package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"astuart.co/vpki"

	"net/http"
	_ "net/http/pprof"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned"
)

var (
	inCluster = flag.Bool("incluster", false, "the client is running inside a kuberenetes cluster")
	ttl       = flag.String("ttl", "240h", "the time to live for certificates")
	role      = flag.String("vault-role", "vault", "the vault role to use when obtaining certs")
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
			Host: "http://desk.astuart.co:8080",
		}
	}

	ttl, err := time.ParseDuration(*ttl)
	if err != nil {
		flag.Usage()
		log.Fatal("Error parsing certificate TTL", err)
	}

	vc := &vpki.Client{
		Addr:     os.Getenv("VAULT_ADDR"),
		Email:    "andrew.stuart2@gmail.com",
		Mount:    "pki",
		Role:     *role,
		Strength: 2048,
		TTL:      ttl,
	}

	log.Println(os.Getenv("ROOT_CA"))
	if os.Getenv("ROOT_CA") != "" {
		cp := x509.NewCertPool()
		cp.AppendCertsFromPEM([]byte(os.Getenv("ROOT_CA")))
		vc.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: cp},
			},
		}
	}

	switch {
	case os.Getenv("VAULT_TOKEN") != "":
		log.Println("Token:", os.Getenv("VAULT_TOKEN"))
		vc.SetToken(strings.TrimSpace(os.Getenv("VAULT_TOKEN")))
	default:
		bs, err := ioutil.ReadFile("~/.vault-token")
		if err != nil {
			log.Fatal(err)
		}
		vc.SetToken(string(bs))
	}

	cli, err := unversioned.New(config)
	if err != nil {
		log.Fatal(err)
	}

	ctr := &certer{c: vc, api: cli}

	go ctr.watchIng()

	for {
		// Initial watch receives all current ingresses; we only need to renew
		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttl)))

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
	}
}
