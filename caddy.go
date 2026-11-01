package castelnuovo

import (
	"errors"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(Auth))
	httpcaddyfile.RegisterHandlerDirective("castelnuovo_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("castelnuovo_auth", httpcaddyfile.Before, "basic_auth")
}

var sessionStores = caddy.NewUsagePool()

type Auth struct {
	ClientID                 string `json:"client_id"`
	ClientSecret             string `json:"client_secret"`
	DisableClientCertificate bool   `json:"disable_client_certificate,omitempty"`

	sessionStoreKey  string
	sessions         *sessionStore
	identityProvider pocketID
	now              func() time.Time
	log              *zap.Logger
}

func (*Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.castelnuovo_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	auth := new(Auth)
	err := auth.UnmarshalCaddyfile(helper.Dispenser)
	return auth, err
}

func (auth *Auth) UnmarshalCaddyfile(dispenser *caddyfile.Dispenser) error {
	dispenser.Next()
	if dispenser.NextArg() {
		return dispenser.ArgErr()
	}
	seenSubdirectives := map[string]bool{}
	for dispenser.NextBlock(0) {
		if seenSubdirectives[dispenser.Val()] {
			return dispenser.Errf("duplicate subdirective '%s'", dispenser.Val())
		}
		seenSubdirectives[dispenser.Val()] = true
		switch dispenser.Val() {
		case "client_id":
			if !dispenser.AllArgs(&auth.ClientID) {
				return dispenser.ArgErr()
			}
		case "client_secret":
			if !dispenser.AllArgs(&auth.ClientSecret) {
				return dispenser.ArgErr()
			}
		case "client_certificate":
			var value string
			if !dispenser.AllArgs(&value) || value != "off" {
				return dispenser.Err("client_certificate only accepts 'off'")
			}
			auth.DisableClientCertificate = true
		default:
			return dispenser.Errf("unrecognized subdirective '%s'", dispenser.Val())
		}
	}
	return nil
}

func (auth *Auth) Provision(ctx caddy.Context) error {
	replacer := caddy.NewReplacer()
	clientID, secret := replacer.ReplaceAll(auth.ClientID, ""), replacer.ReplaceAll(auth.ClientSecret, "")
	switch {
	case clientID == "":
		return errors.New("client_id is empty")
	case secret == "":
		return errors.New("client_secret is empty")
	}

	store, _, err := sessionStores.LoadOrNew(clientID, func() (caddy.Destructor, error) {
		return newSessionStore(), nil
	})
	if err != nil {
		return err
	}
	auth.sessionStoreKey, auth.sessions = clientID, store.(*sessionStore)
	auth.identityProvider = newOIDCClient(issuer, clientID, secret, &http.Client{Timeout: 10 * time.Second})
	auth.now = time.Now
	auth.log = ctx.Logger()
	return nil
}

func (auth *Auth) Cleanup() error {
	_, err := sessionStores.Delete(auth.sessionStoreKey)
	return err
}

var (
	_ caddy.Provisioner           = (*Auth)(nil)
	_ caddy.CleanerUpper          = (*Auth)(nil)
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
