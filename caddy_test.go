package castelnuovo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyfileDirective(t *testing.T) {
	adaptedJSON, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(`app.castelnuovo.eu {
	respond ok
	castelnuovo_auth {
		client_id {env.CLIENT_ID}
		client_secret {env.CLIENT_SECRET}
	}
}`), nil)
	config := string(adaptedJSON)
	authPosition, respondPosition := strings.Index(config, `"handler":"castelnuovo_auth"`), strings.Index(config, `"handler":"static_response"`)
	if err != nil || authPosition < 0 || respondPosition < authPosition || !strings.Contains(config, `"client_id":"{env.CLIENT_ID}"`) {
		t.Fatalf("%v %s", err, config)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	var auth Auth
	err := auth.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`castelnuovo_auth {
		client_id {env.CLIENT_ID}
		client_secret secret
		client_certificate off
	}`))
	if err != nil || auth.ClientID != "{env.CLIENT_ID}" || auth.ClientSecret != "secret" || !auth.DisableClientCertificate {
		t.Fatalf("%v %+v", err, &auth)
	}

	for name, input := range map[string]string{
		"argument":               "castelnuovo_auth client",
		"unknown subdirective":   "castelnuovo_auth {\n client_name x\n}",
		"missing value":          "castelnuovo_auth {\n client_id\n}",
		"missing secret":         "castelnuovo_auth {\n client_secret\n}",
		"two values":             "castelnuovo_auth {\n client_id a b\n}",
		"certificate on":         "castelnuovo_auth {\n client_certificate on\n}",
		"certificate without":    "castelnuovo_auth {\n client_certificate\n}",
		"duplicate subdirective": "castelnuovo_auth {\n client_id a\n client_id b\n}",
	} {
		var auth Auth
		if err := auth.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Fatalf("%s: accepted %+v", name, &auth)
		}
	}
}

func TestProvision(t *testing.T) {
	t.Setenv("TEST_CASTELNUOVO_CLIENT_ID", "client")
	t.Setenv("TEST_CASTELNUOVO_CLIENT_SECRET", "secret")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	provision := func(clientID string) *Auth {
		t.Helper()
		auth := &Auth{ClientID: clientID, ClientSecret: "{env.TEST_CASTELNUOVO_CLIENT_SECRET}"}
		if err := auth.Provision(ctx); err != nil || auth.identityProvider == nil || auth.identityProvider.(*oidcClient).httpClient.Timeout == 0 {
			t.Fatalf("%v %+v", err, auth)
		}
		return auth
	}
	first := provision("{env.TEST_CASTELNUOVO_CLIENT_ID}")
	now := time.Now()
	id := first.sessions.add(session{expiresAt: now.Add(time.Hour)}, now)
	reloaded, other := provision("client"), provision("other-client")
	if _, found := reloaded.sessions.get(id); !found {
		t.Fatal("a config reload lost the session")
	}
	if other.sessions == first.sessions {
		t.Fatal("two OIDC clients share a session store")
	}
	for _, auth := range []*Auth{first, reloaded, other} {
		if err := auth.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	fresh := provision("client")
	defer fresh.Cleanup()
	if _, found := fresh.sessions.get(id); found {
		t.Fatal("the session store outlived its last site")
	}

	for _, auth := range []*Auth{{ClientSecret: "secret"}, {ClientID: "client"}, {ClientID: "{env.TEST_CASTELNUOVO_MISSING}", ClientSecret: "secret"}} {
		if err := auth.Provision(ctx); err == nil {
			t.Fatalf("provisioned %+v", auth)
		}
	}
}
