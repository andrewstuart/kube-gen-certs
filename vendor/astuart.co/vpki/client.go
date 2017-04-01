package vpki

import (
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
)

type secretWriter interface {
	Write(string, map[string]interface{}) (*api.Secret, error)
}

// Client is the abstraction for a vault client, with convenience methods for
// obtaining golang tls.Certificates with minimum risk of key disclosure (keys
// are generated locally then CSRs sent to Vault).
type Client struct {
	Mount, Role, Addr, Email string
	Strength                 int
	TTL                      time.Duration
	HTTPClient               *http.Client

	vc *api.Client
	sw secretWriter
}

func (c *Client) init() error {
	if c.Strength == 0 {
		c.Strength = 2048
	}

	if c.sw == nil {
		var err error

		cfg := &api.Config{
			Address:    c.Addr,
			HttpClient: c.HTTPClient,
		}

		c.vc, err = api.NewClient(cfg)
		if err != nil {
			return err
		}

		c.sw = c.vc.Logical()
	}

	return nil
}

// SetToken sets the Vault token for the Client.
func (c *Client) SetToken(t string) {
	c.init()
	c.vc.SetToken(t)
	c.sw = c.vc.Logical()
}

// // NewClient returns a client configured for the endpoints specified
// func NewClient(addr, mount, role string) (*Client, error) {
// 	panic("not implemented")
// 	return nil, nil
// }
