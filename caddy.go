package castelnuovo

import (
	"errors"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Auth{})
	httpcaddyfile.RegisterHandlerDirective("castelnuovo_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("castelnuovo_auth", httpcaddyfile.Before, "basic_auth")
}

var stores = caddy.NewUsagePool()

type Auth struct {
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	DisableYubikey bool   `json:"disable_yubikey,omitempty"`

	storeKey string
	store    *store
	idp      pocketID
	now      func() time.Time
	log      *zap.Logger
}

func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.castelnuovo_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (m *Auth) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	clientID := repl.ReplaceAll(m.ClientID, "")
	secret := repl.ReplaceAll(m.ClientSecret, "")
	if clientID == "" || secret == "" {
		return errors.New("client_id and client_secret are required")
	}

	st, _, err := stores.LoadOrNew(clientID, func() (caddy.Destructor, error) { return newStore(), nil })
	if err != nil {
		return err
	}
	m.storeKey = clientID
	m.store = st.(*store)
	m.idp = newOIDC(clientID, secret)
	m.now = time.Now
	m.log = ctx.Logger()
	return nil
}

func (m *Auth) Cleanup() error {
	_, err := stores.Delete(m.storeKey)
	return err
}

func (m *Auth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "client_id":
			if !d.AllArgs(&m.ClientID) {
				return d.ArgErr()
			}
		case "client_secret":
			if !d.AllArgs(&m.ClientSecret) {
				return d.ArgErr()
			}
		case "yubikey":
			var value string
			if !d.AllArgs(&value) || value != "off" {
				return d.Err("yubikey only accepts off")
			}
			m.DisableYubikey = true
		default:
			return d.Errf("unknown subdirective %q", d.Val())
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
	_ caddy.CleanerUpper          = (*Auth)(nil)
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
