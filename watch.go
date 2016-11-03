package main

import (
	"encoding/json"
	"log"
	"os"

	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/kubernetes/pkg/watch"
)

func (ctr *certer) watchIng() {
	for {
		w, err := ctr.api.Ingresses("").Watch(v1.ListOptions{})
		if err != nil {
			log.Fatal("Watch error", err)
			return
		}

		for evt := range w.ResultChan() {
			et := watch.EventType(evt.Type)
			if et != watch.Added && et != watch.Modified {
				continue
			}

			switch o := evt.Object.(type) {
			case *v1beta1.Ingress:
				_, err = ctr.addTLSSecrets(o)
				if err != nil {
					log.Printf("Error adding secret for new/updated ingress: %s/%s: %s", o.Namespace, o.Name, err)
				}
			default:
				log.Println("Some crazy error")
				log.Println(json.NewEncoder(os.Stdout).Encode(o))
			}
		}

		log.Println("Result channel closed. Starting again.")
	}
}
