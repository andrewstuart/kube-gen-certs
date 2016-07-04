package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
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

	go ctr.watchIng()

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

		// Sleep for 90% of the TTL before reissue
		time.Sleep(time.Duration(0.9 * float64(ttlD)))
	}
}

func (ctr *certer) addTLSSecrets(ing *extensions.Ingress) (*extensions.Ingress, error) {
	if len(ing.Spec.TLS) == 0 && !*forceTLS {
		return nil, fmt.Errorf("No ingresses to update")
	}

	var err error

	fmt.Println(ing.Name)

	if *forceTLS {
		ing.Spec.TLS = []extensions.IngressTLS{}
		for _, rule := range ing.Spec.Rules {
			ing.Spec.TLS = append(ing.Spec.TLS, extensions.IngressTLS{
				Hosts:      []string{rule.Host},
				SecretName: rule.Host + ".tls",
			})
		}

		ing, err := ctr.api.Extensions().Ingress(ing.Namespace).Update(ing)
		if err != nil {
			return nil, fmt.Errorf("Error updating ingress %s/%s: %s", ing.Namespace, ing.Name, err)
		}
	}

	for _, tls := range ing.Spec.TLS {
		if len(tls.Hosts) < 1 {
			continue
		}

		var sec *api.Secret
		var newSec bool

		sec, err = ctr.api.Secrets(ing.Namespace).Get(tls.SecretName)
		if err != nil {
			newSec = true
			log.Println("Error getting secret", tls.SecretName, err)
			sec = &api.Secret{
				ObjectMeta: api.ObjectMeta{
					Namespace: ing.Namespace,
					Name:      tls.SecretName,
				},
				Data: map[string][]byte{},
			}
		}

		h := tls.Hosts[0]
		//TODO maybe do altnames here? The Ingress TLS struct is weirdly redundant.
		m, err := vpki.RawCert(ctr.c, h)
		if err != nil {
			log.Printf("Error getting raw certificate for %s: %s", h, err)
			continue
		}

		log.Println(string(m.Public))

		sec.Data["tls.key"] = m.Private
		sec.Data["tls.crt"] = m.Public
		var op string

		if newSec {
			op = "creating"
			sec, err = ctr.api.Secrets(ing.Namespace).Create(sec)
		} else {
			op = "updating"
			sec, err = ctr.api.Secrets(ing.Namespace).Update(sec)
		}

		if err != nil {
			log.Printf("Error %s secret %s: %s", op, sec.Name, err)
		}
	}

	return ing, nil
}

func (ctr *certer) watchIng() {
	w, err := ctr.api.Extensions().Ingress("").Watch(api.ListOptions{})
	if err != nil {
		log.Println("Watch error", err)
		return
	}

	for evt := range w.ResultChan() {
		et := watch.EventType(evt.Type)
		if et != watch.Added && et != watch.Modified {
			continue
		}

		originalObjJS, err := runtime.Encode(api.Codecs.LegacyCodec(), evt.Object)
		if err != nil {
			log.Println("Object decode error", err)
			continue
		}

		i := &extensions.Ingress{}
		err = json.Unmarshal(originalObjJS, i)
		if err != nil {
			log.Println("Ingress Unmarshal error", err)
			continue
		}

		_, err = ctr.addTLSSecrets(i)
		if err != nil {
			log.Printf("Error adding secret for new/updated ingress: %s/%s: %s", i.Namespace, i.Name, err)
		}
	}
}
