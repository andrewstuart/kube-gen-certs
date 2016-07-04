package main

import (
	"encoding/json"
	"log"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
)

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
