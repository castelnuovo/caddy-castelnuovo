package castelnuovo

import (
	"crypto/cipher"
	"errors"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

func init() {
	caddy.RegisterModule(new(Auth))
	httpcaddyfile.RegisterHandlerDirective("castelnuovo_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("castelnuovo_auth", httpcaddyfile.Before, "basic_auth")
}

type Auth struct {
	ClientID                 string `json:"client_id"`
	ClientSecret             string `json:"client_secret"`
	DisableClientCertificate bool   `json:"disable_client_certificate,omitempty"`

	aead      cipher.AEAD
	idp       pocketID
	refreshes singleflight.Group
	now       func() time.Time
	log       *zap.Logger
}

func (*Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.castelnuovo_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (m *Auth) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	clientID, secret := repl.ReplaceAll(m.ClientID, ""), repl.ReplaceAll(m.ClientSecret, "")
	switch {
	case clientID == "":
		return errors.New("client_id is empty")
	case secret == "":
		return errors.New("client_secret is empty")
	}

	aead, err := newAEAD(secret)
	if err != nil {
		return err
	}
	m.aead = aead
	m.idp = newOIDC(issuer, clientID, secret, &http.Client{Timeout: 10 * time.Second})
	m.now = time.Now
	m.log = ctx.Logger()
	return nil
}

func (m *Auth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	seen := map[string]bool{}
	for d.NextBlock(0) {
		if seen[d.Val()] {
			return d.Errf("duplicate subdirective '%s'", d.Val())
		}
		seen[d.Val()] = true
		switch d.Val() {
		case "client_id":
			if !d.AllArgs(&m.ClientID) {
				return d.ArgErr()
			}
		case "client_secret":
			if !d.AllArgs(&m.ClientSecret) {
				return d.ArgErr()
			}
		case "client_certificate":
			var value string
			if !d.AllArgs(&value) || value != "off" {
				return d.Err("client_certificate only accepts 'off'")
			}
			m.DisableClientCertificate = true
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Auth)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var (
	_ caddy.Provisioner           = (*Auth)(nil)
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
