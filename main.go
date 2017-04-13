package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"astuart.co/vpki"

	"net/http"
	_ "net/http/pprof"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"
)

var (
	inCluster  = flag.Bool("incluster", false, "the client is running inside a kuberenetes cluster")
	ttl        = flag.String("ttl", "240h", "the time to live for certificates")
	forceTLS   = flag.Bool("forcetls", false, "force all ingresses to use TLS if certs can be obtained")
	role       = flag.String("vault-role", "vault", "the vault role to use when obtaining certs")
	selfSigned = flag.Bool("self-signed", false, "self-sign all certificates")
	certNS     = flag.String("cert-namespace", "", "the namespace in which certificates should be created")
)

func init() {
	flag.Parse()
	log.SetFormatter(&log.JSONFormatter{})
}

type certer struct {
	c         vpki.Certifier
	api       *kubernetes.Clientset
	namespace string
}

func main() {
	var config *rest.Config

	log.Printf("TTL: %s, inCluster: %t", *ttl, *inCluster)

	if *inCluster {
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		config = &rest.Config{
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

	var ctr *certer

	if !*selfSigned {
		switch {
		case os.Getenv("VAULT_TOKEN") != "":
			log.Debug("Token:", os.Getenv("VAULT_TOKEN"))
			vc.SetToken(strings.TrimSpace(os.Getenv("VAULT_TOKEN")))
		default:
			bs, err := ioutil.ReadFile("~/.vault-token")
			if err != nil {
				log.Fatal(err)
			}
			vc.SetToken(string(bs))
		}
	}

	cli, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	if !*selfSigned {
		ctr = &certer{
			c:   vc,
			api: cli,
		}
	} else {
		ctr = &certer{
			c:   &vpki.RawMarshaler{RawCertifier: &SelfSigner{ttl}},
			api: cli,
		}
	}

	ctr.namespace = *certNS

	go ctr.watchIng()

	for {
		// Initial watch receives all current ingresses; we only need to renew
		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttl)))

		ns, err := cli.Namespaces().List(v1.ListOptions{})
		if err != nil {
			log.Fatal(err)
		}

		for _, n := range ns.Items {
			i := cli.Ingresses(n.Name)

			li, err := i.List(v1.ListOptions{})
			if err != nil {
				log.Fatal(err)
			}

			for _, ing := range li.Items {
				_, err := ctr.addTLSSecrets(&ing)
				if err != nil {
					log.WithFields(log.Fields{
						"ingress":   ing.Name,
						"namespace": ing.Namespace,
					}).Println(err)
				}
			}
		}
	}
}
