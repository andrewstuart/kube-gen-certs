package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"go.astuart.co/vpki"

	"net/http"
	_ "net/http/pprof"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned"
)

var (
	inCluster = flag.Bool("incluster", false, "the client is running inside a kuberenetes cluster")
	ttl       = flag.String("ttl", "240h", "the time to live for certificates")
	forceTLS  = flag.Bool("forcetls", false, "force all ingresses to use TLS")
)

func init() {
	flag.Parse()
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
		log.Fatal(err)
	}

	vc := &vpki.Client{
		Addr:     os.Getenv("VAULT_ADDR"),
		Email:    "andrew.stuart2@gmail.com",
		Mount:    "pki",
		Role:     "astuart",
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
		vc.SetToken(os.Getenv("VAULT_TOKEN"))
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
				if len(ing.Spec.TLS) == 0 && !*forceTLS {
					continue
				}

				fmt.Println(ing.Name)

				if len(ing.Spec.TLS) < 1 {
					newT := extensions.IngressTLS{
						Hosts:      []string{ing.Spec.Rules[0].Host},
						SecretName: ing.Spec.Rules[0].Host + ".tls",
					}
					ing.Spec.TLS = []extensions.IngressTLS{newT}
				}

				_, err = cli.Extensions().Ingress(n.Name).Update(&ing)
				if err != nil {
					log.Println(err)
					continue
				}

				for _, tls := range ing.Spec.TLS {
					if len(tls.Hosts) < 1 {
						continue
					}

					m, err := vpki.RawCert(vc, tls.Hosts[0])
					if err != nil {
						log.Println("Error getting raw certificate", err)
						continue
					}

					sec, err := cli.Secrets(n.Name).Get(tls.SecretName)
					if err != nil {
						log.Println("Error getting secret", tls.SecretName, err)
						continue
					}

					log.Println(string(m.Public))

					sec.Data["tls.key"] = m.Private
					sec.Data["tls.crt"] = m.Public

					_, err = cli.Secrets(n.Name).Update(sec)
					if err != nil {
						log.Println("Error updating secret", sec.Name, err)
					}
				}

				fmt.Println(ing.Spec.TLS)
			}

			//LF
			fmt.Println()
		}

		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttl)))
	}
}
