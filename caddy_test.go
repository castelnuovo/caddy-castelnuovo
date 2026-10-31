package castelnuovo

import (
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	var m Auth
	err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`castelnuovo_auth {
		client_id {env.CLIENT_ID}
		client_secret secret
		client_certificate off
	}`))
	if err != nil || m.ClientID != "{env.CLIENT_ID}" || m.ClientSecret != "secret" || !m.DisableClientCertificate {
		t.Fatalf("%v %+v", err, m)
	}

	for name, input := range map[string]string{
		"argument":               "castelnuovo_auth client",
		"unknown subdirective":   "castelnuovo_auth {\n client_name x\n}",
		"missing value":          "castelnuovo_auth {\n client_id\n}",
		"missing secret":         "castelnuovo_auth {\n client_secret\n}",
		"two values":             "castelnuovo_auth {\n client_id a b\n}",
		"certificate on":         "castelnuovo_auth {\n client_certificate on\n}",
		"duplicate subdirective": "castelnuovo_auth {\n client_id a\n client_id b\n}",
	} {
		var m Auth
		if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Fatalf("%s: accepted %+v", name, m)
		}
	}
}

func TestCaddyfileDirective(t *testing.T) {
	out, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(`app.castelnuovo.eu {
	respond ok
	castelnuovo_auth {
		client_id {env.CLIENT_ID}
		client_secret {env.CLIENT_SECRET}
	}
}`), nil)
	config := string(out)
	auth, respond := strings.Index(config, `"handler":"castelnuovo_auth"`), strings.Index(config, `"handler":"static_response"`)
	if err != nil || auth < 0 || respond < auth || !strings.Contains(config, `"client_id":"{env.CLIENT_ID}"`) {
		t.Fatalf("%v %s", err, config)
	}
}

func TestProvision(t *testing.T) {
	t.Setenv("TEST_CASTELNUOVO_CLIENT_ID", "provision-client")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	provision := func() *Auth {
		t.Helper()
		m := &Auth{ClientID: "{env.TEST_CASTELNUOVO_CLIENT_ID}", ClientSecret: "secret"}
		if err := m.Provision(ctx); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cleanup := func(m *Auth) {
		t.Helper()
		if err := m.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}

	first := provision()
	if first.storeKey != "provision-client" || first.store == nil || first.idp == nil {
		t.Fatalf("provisioned %+v", first)
	}
	reloaded := provision()
	cleanup(first)
	if reloaded.store != first.store {
		t.Fatal("a reload starts a new store")
	}
	cleanup(reloaded)
	restarted := provision()
	defer cleanup(restarted)
	if restarted.store == first.store {
		t.Fatal("the store outlives every handler")
	}

	for _, m := range []*Auth{{ClientSecret: "secret"}, {ClientID: "client"}, {ClientID: "{env.TEST_CASTELNUOVO_MISSING}", ClientSecret: "secret"}} {
		if err := m.Provision(ctx); err == nil {
			t.Fatalf("provisioned %+v", m)
		}
		cleanup(m)
	}
}
