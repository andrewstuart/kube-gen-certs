package main

import (
	"testing"

	"k8s.io/client-go/pkg/apis/extensions/v1beta1"

	"github.com/stretchr/testify/assert"
)

func TestMissingCerts(t *testing.T) {
	asrt := assert.New(t)

	rules := []v1beta1.IngressRule{{
		Host: "foo.astuart.co",
	}, {
		Host: "bar.astuart.co",
	}}

	tls := []v1beta1.IngressTLS{{
		Hosts: []string{"blab.astuart.co", "bar.astuart.co"},
	}, {
		Hosts: []string{"bang.astuart.co"},
	}}

	m := missingHosts(rules, tls)

	asrt.Len(m, 1)
	asrt.Equal("foo.astuart.co", m[0])
}
