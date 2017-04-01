package vpki

import (
	"crypto/tls"
	"sync"
	"time"
)

type certCache struct {
	m   map[string]*tls.Certificate
	mut *sync.RWMutex
	crt Certifier
	ttl time.Duration
}

func newCertCache(crt Certifier) *certCache {
	return &certCache{
		m:   map[string]*tls.Certificate{},
		mut: &sync.RWMutex{},
		crt: crt,
		ttl: DefaultTTL,
	}
}

func (cc *certCache) add(name string) (*tls.Certificate, error) {
	crt, err := cc.crt.Cert(name)
	if err != nil {
		return nil, err
	}

	cc.mut.Lock()
	cc.m[name] = crt
	cc.mut.Unlock()
	return crt, nil
}

func (cc *certCache) get(name string) (*tls.Certificate, error) {
	lkr := cc.mut.RLocker()
	lkr.Lock()

	if c, ok := cc.m[name]; ok {
		n := time.Now()
		if n.After(c.Leaf.NotBefore) && n.Before(c.Leaf.NotAfter) {
			lkr.Unlock()
			return c, nil
		}
	}
	lkr.Unlock()

	return cc.add(name)
}
