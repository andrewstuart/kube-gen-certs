package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"

	"astuart.co/vpki"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (ctr *certer) addTLSSecrets(ing *v1beta1.Ingress) (*v1beta1.Ingress, error) {
	if len(ing.Spec.TLS) == 0 && !*forceTLS {
		log.Println(*forceTLS)
		return nil, fmt.Errorf("No ingress to update")
	}

	var err error

	fmt.Println(ing.Name)

	if *forceTLS {
		ing.Spec.TLS = []v1beta1.IngressTLS{}
		for _, rule := range ing.Spec.Rules {
			ing.Spec.TLS = append(ing.Spec.TLS, v1beta1.IngressTLS{
				Hosts:      []string{rule.Host},
				SecretName: rule.Host + ".tls",
			})
		}

		ing, err := ctr.api.Ingresses(ing.Namespace).Update(ing)
		if err != nil {
			return nil, fmt.Errorf("Error updating ingress %s/%s: %s", ing.Namespace, ing.Name, err)
		}
	}

	for _, tls := range ing.Spec.TLS {
		if len(tls.Hosts) < 1 {
			continue
		}

		var sec *v1.Secret
		var newSec bool

		sec, err = ctr.api.Secrets(ing.Namespace).Get(tls.SecretName)
		if err != nil {
			newSec = true
			log.Println("Error getting secret", tls.SecretName, err)
			sec = &v1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Namespace: ing.Namespace,
					Name:      tls.SecretName,
				},
				Data: map[string][]byte{},
			}
		}

		var keyPair *vpki.RawPair

		switch certer := ctr.c.(type) {
		case *vpki.Client:
			csr := &x509.CertificateRequest{
				DNSNames: tls.Hosts,
				Subject: pkix.Name{
					CommonName: tls.Hosts[0],
				},
			}

			keyPair, err = certer.GenCert(csr)
		default:
			keyPair, err = vpki.RawCert(certer, tls.Hosts[0])
		}

		if err != nil {
			return nil, fmt.Errorf("error getting raw certificate for secret %s: %s", tls.SecretName, err)
		}

		log.Println(string(keyPair.Public))

		sec.Data["tls.key"] = keyPair.Private
		sec.Data["tls.crt"] = keyPair.Public
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
