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

func TestProvision(t *testing.T) {
	t.Setenv("TEST_CASTELNUOVO_CLIENT_ID", "client")
	t.Setenv("TEST_CASTELNUOVO_CLIENT_SECRET", "secret")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	provision := func(secret string) *Auth {
		t.Helper()
		auth := &Auth{ClientID: "{env.TEST_CASTELNUOVO_CLIENT_ID}", ClientSecret: secret}
		if err := auth.Provision(ctx); err != nil || auth.identityProvider == nil || auth.identityProvider.(*oidcClient).httpClient.Timeout == 0 {
			t.Fatalf("%v %+v", err, auth)
		}
		return auth
	}
	first := provision("{env.TEST_CASTELNUOVO_CLIENT_SECRET}")
	cookie, err := first.sealCookie(sessionCookieName, session{Host: host}, 60)
	if err != nil {
		t.Fatal(err)
	}

	var stored session
	if err := provision("secret").openCookie(sessionCookieName, cookie.Value, &stored); err != nil || stored.Host != host {
		t.Fatalf("after a restart: %v", err)
	}
	if err := provision("other secret").openCookie(sessionCookieName, cookie.Value, &stored); err == nil {
		t.Fatal("another client secret opened the cookie")
	}

	for _, auth := range []*Auth{{ClientSecret: "secret"}, {ClientID: "client"}, {ClientID: "{env.TEST_CASTELNUOVO_MISSING}", ClientSecret: "secret"}} {
		if err := auth.Provision(ctx); err == nil {
			t.Fatalf("provisioned %+v", auth)
		}
	}
}
