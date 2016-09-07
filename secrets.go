package main

import (
	"fmt"
	"log"

	"astuart.co/vpki"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

func (ctr *certer) addTLSSecrets(ing *extensions.Ingress) (*extensions.Ingress, error) {
	if len(ing.Spec.TLS) == 0 && !*forceTLS {
		log.Println(*forceTLS)
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
			return nil, fmt.Errorf("Error getting raw certificate for %s: %s", h, err)
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
			return nil, fmt.Errorf("Error %s secret %s: %s", op, sec.Name, err)
		}
	}

	return ing, nil
}
