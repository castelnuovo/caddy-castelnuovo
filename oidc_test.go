package castelnuovo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type tokenRequest struct {
	form           url.Values
	user, password string
}

type testIdP struct {
	*httptest.Server
	key        *rsa.PrivateKey
	claims     map[string]any
	status     int
	jwksStatus int
	omit       string
	tokens     chan tokenRequest
}

func newIdP(t *testing.T) *testIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{key: key, tokens: make(chan tokenRequest, 10)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if p.jwksStatus != 0 {
			w.WriteHeader(p.jwksStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /api/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, password, _ := r.BasicAuth()
		p.tokens <- tokenRequest{r.PostForm, user, password}
		w.Header().Set("Content-Type", "application/json")
		if p.status != 0 {
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		response := map[string]any{
			"access_token":  "access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"id_token":      p.sign(),
			"refresh_token": "new-refresh-token",
		}
		delete(response, p.omit)
		_ = json.NewEncoder(w).Encode(response)
	})
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Close)
	p.claims = map[string]any{
		"iss":       p.URL,
		"aud":       "client",
		"sub":       sub,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"nonce":     "nonce",
		"amr":       []string{"phr"},
		"auth_time": time.Now().Unix(),
		"groups":    []string{"admins"},
	}
	return p
}

func (p *testIdP) sign() string {
	payload, _ := json.Marshal(p.claims)
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, _ := rsa.SignPKCS1v15(nil, p.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (p *testIdP) client() *oidcClient {
	return newOIDC(p.URL, "client", "secret", p.Client())
}

func TestOIDCAuthURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", http.DefaultClient)
	verifier := oauth2.GenerateVerifier()
	for _, reauth := range []bool{false, true} {
		u, _ := url.Parse(o.authURL("https://"+host+callbackPath, "state", "nonce", verifier, reauth))
		want := url.Values{
			"client_id":             {"client"},
			"redirect_uri":          {"https://" + host + callbackPath},
			"response_type":         {"code"},
			"scope":                 {"openid profile email groups offline_access"},
			"state":                 {"state"},
			"nonce":                 {"nonce"},
			"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
			"code_challenge_method": {"S256"},
			"max_age":               {"3600"},
		}
		if reauth {
			want.Set("prompt", "login")
		}
		if u.Scheme+"://"+u.Host+u.Path != issuer+"/authorize" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("reauth %v: %s", reauth, u)
		}
	}
}

func TestOIDCExchange(t *testing.T) {
	p := newIdP(t)
	c, refreshToken, err := p.client().exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
	if err != nil || c.Subject != sub || c.Nonce != "nonce" || !slices.Equal(c.AMR, []string{"phr"}) || !slices.Equal(c.Groups, []string{"admins"}) || c.idToken == "" || refreshToken != "new-refresh-token" {
		t.Fatalf("%v %+v %q", err, c, refreshToken)
	}

	req := <-p.tokens
	want := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code"},
		"code_verifier": {"verifier"},
		"redirect_uri":  {"https://" + host + callbackPath},
	}
	if req.user != "client" || req.password != "secret" || !maps.EqualFunc(req.form, want, slices.Equal[[]string]) {
		t.Fatalf("token request: %+v", req)
	}
}

func TestOIDCExchangeFails(t *testing.T) {
	tests := map[string]struct {
		change      func(*testIdP)
		requests    int
		unavailable bool
	}{
		"code rejected":    {func(p *testIdP) { p.status = http.StatusBadRequest }, 1, false},
		"server error":     {func(p *testIdP) { p.status = http.StatusServiceUnavailable }, 1, true},
		"rate limited":     {func(p *testIdP) { p.status = http.StatusTooManyRequests }, 1, true},
		"unreachable":      {func(p *testIdP) { p.Close() }, 0, true},
		"no ID token":      {func(p *testIdP) { p.omit = "id_token" }, 1, false},
		"no refresh token": {func(p *testIdP) { p.omit = "refresh_token" }, 1, false},
		"another audience": {func(p *testIdP) { p.claims["aud"] = "other" }, 1, false},
		"expired ID token": {func(p *testIdP) { p.claims["exp"] = time.Now().Add(-time.Hour).Unix() }, 1, false},
		"malformed claims": {func(p *testIdP) { p.claims["auth_time"] = "yesterday" }, 1, false},
		"keys unavailable": {func(p *testIdP) { p.jwksStatus = http.StatusServiceUnavailable }, 1, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := newIdP(t)
			o := p.client()
			tt.change(p)
			_, _, err := o.exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
			if err == nil || errors.Is(err, errUnavailable) != tt.unavailable || len(p.tokens) != tt.requests {
				t.Fatalf("error %v after %d token requests", err, len(p.tokens))
			}
		})
	}
}

func TestOIDCRefresh(t *testing.T) {
	p := newIdP(t)
	o := p.client()

	p.omit = "refresh_token"
	c, refreshToken, err := o.refresh(context.Background(), "old-refresh-token")
	if err != nil || c.Subject != sub || refreshToken != "old-refresh-token" {
		t.Fatalf("%v %+v %q", err, c, refreshToken)
	}
	req := <-p.tokens
	want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"old-refresh-token"}}
	if req.user != "client" || req.password != "secret" || !maps.EqualFunc(req.form, want, slices.Equal[[]string]) {
		t.Fatalf("token request: %+v", req)
	}

	p.status = http.StatusBadRequest
	if _, _, err := o.refresh(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) {
		t.Fatalf("rejected refresh token: %v", err)
	}
	p.status = http.StatusBadGateway
	if _, _, err := o.refresh(context.Background(), "old-refresh-token"); !errors.Is(err, errUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

func TestOIDCLogoutURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", http.DefaultClient)
	redirect := "https://" + host + "/"
	for idToken, want := range map[string]url.Values{
		"id-token": {"id_token_hint": {"id-token"}, "client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
		"":         {"client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
	} {
		u, _ := url.Parse(o.logoutURL(idToken, redirect))
		if u.Scheme+"://"+u.Host+u.Path != issuer+"/api/oidc/end-session" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("ID token %q: %s", idToken, u)
		}
	}
}
