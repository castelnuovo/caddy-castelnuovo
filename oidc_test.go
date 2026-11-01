package castelnuovo

import (
	"cmp"
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

const testIssuer = "https://id.test"

type tokenRequest struct {
	form           url.Values
	user, password string
}

type testIdP struct {
	key        *rsa.PrivateKey
	signer     *rsa.PrivateKey
	claims     map[string]any
	down       bool
	status     int
	jwksStatus int
	omit       string
	requests   []tokenRequest
}

func (p *testIdP) RoundTrip(r *http.Request) (*http.Response, error) {
	if p.down {
		return nil, errors.New("connection refused")
	}
	rec := httptest.NewRecorder()
	switch r.URL.String() {
	case testIssuer + "/.well-known/jwks.json":
		p.jwks(rec)
	case testIssuer + "/api/oidc/token":
		p.token(rec, r)
	default:
		rec.WriteHeader(http.StatusNotFound)
	}
	return rec.Result(), nil
}

func (p *testIdP) jwks(w http.ResponseWriter) {
	if p.jwksStatus != 0 {
		w.WriteHeader(p.jwksStatus)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "test",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func (p *testIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	user, password, _ := r.BasicAuth()
	p.requests = append(p.requests, tokenRequest{r.PostForm, user, password})
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
}

func (p *testIdP) sign() string {
	payload, _ := json.Marshal(p.claims)
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, _ := rsa.SignPKCS1v15(nil, cmp.Or(p.signer, p.key), crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newIdP(t *testing.T) (*testIdP, *oidcClient) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{key: key, claims: map[string]any{
		"iss":       testIssuer,
		"aud":       "client",
		"sub":       sub,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"nonce":     "nonce",
		"amr":       []string{"phr"},
		"auth_time": time.Now().Unix(),
		"groups":    []string{"admins"},
	}}
	return p, newOIDC(testIssuer, "client", "secret", &http.Client{Transport: p})
}

func TestOIDCAuthURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", nil)
	verifier := oauth2.GenerateVerifier()
	u := must(url.Parse(o.authURL("https://"+host+callbackPath, "state", "nonce", verifier)))
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
	if u.Scheme+"://"+u.Host+u.Path != issuer+"/authorize" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
		t.Fatalf("%s", u)
	}
}

func TestOIDCExchange(t *testing.T) {
	p, o := newIdP(t)
	got, err := o.exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
	c, _ := parseClaims(got.idToken)
	if err != nil || got.refreshToken != "new-refresh-token" || c.Subject != sub || c.Nonce != "nonce" || !slices.Equal(c.AMR, []string{"phr"}) || !slices.Equal(c.Groups, []string{"admins"}) {
		t.Fatalf("%v %+v %+v", err, got, c)
	}

	want := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code"},
		"code_verifier": {"verifier"},
		"redirect_uri":  {"https://" + host + callbackPath},
	}
	if len(p.requests) != 1 || p.requests[0].user != "client" || p.requests[0].password != "secret" || !maps.EqualFunc(p.requests[0].form, want, slices.Equal[[]string]) {
		t.Fatalf("token requests: %+v", p.requests)
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
		"unreachable":      {func(p *testIdP) { p.down = true }, 0, true},
		"no ID token":      {func(p *testIdP) { p.omit = "id_token" }, 1, false},
		"no refresh token": {func(p *testIdP) { p.omit = "refresh_token" }, 1, false},
		"another audience": {func(p *testIdP) { p.claims["aud"] = "other" }, 1, false},
		"another issuer":   {func(p *testIdP) { p.claims["iss"] = "https://evil.example" }, 1, false},
		"expired ID token": {func(p *testIdP) { p.claims["exp"] = time.Now().Add(-time.Hour).Unix() }, 1, false},
		"another signer":   {func(p *testIdP) { p.signer = must(rsa.GenerateKey(rand.Reader, 2048)) }, 1, false},
		"keys unavailable": {func(p *testIdP) { p.jwksStatus = http.StatusServiceUnavailable }, 1, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p, o := newIdP(t)
			tt.change(p)
			_, err := o.exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
			if err == nil || errors.Is(err, errUnavailable) != tt.unavailable || len(p.requests) != tt.requests {
				t.Fatalf("error %v after %d token requests", err, len(p.requests))
			}
		})
	}
}

func TestOIDCRefresh(t *testing.T) {
	p, o := newIdP(t)
	got, err := o.refresh(context.Background(), "old-refresh-token")
	if c, _ := parseClaims(got.idToken); err != nil || c.Subject != sub || got.refreshToken != "new-refresh-token" {
		t.Fatalf("%v %+v", err, got)
	}
	want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"old-refresh-token"}}
	if len(p.requests) != 1 || p.requests[0].user != "client" || p.requests[0].password != "secret" || !maps.EqualFunc(p.requests[0].form, want, slices.Equal[[]string]) {
		t.Fatalf("token requests: %+v", p.requests)
	}

	p.status = http.StatusBadRequest
	if _, err := o.refresh(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) {
		t.Fatalf("rejected refresh token: %v", err)
	}
	p.status = http.StatusBadGateway
	if _, err := o.refresh(context.Background(), "old-refresh-token"); !errors.Is(err, errUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

func TestOIDCRefreshVerifiesIDToken(t *testing.T) {
	for name, change := range map[string]func(*testIdP){
		"no ID token":      func(p *testIdP) { p.omit = "id_token" },
		"another audience": func(p *testIdP) { p.claims["aud"] = "other" },
		"another issuer":   func(p *testIdP) { p.claims["iss"] = "https://evil.example" },
		"expired ID token": func(p *testIdP) { p.claims["exp"] = time.Now().Add(-time.Hour).Unix() },
		"another signer":   func(p *testIdP) { p.signer = must(rsa.GenerateKey(rand.Reader, 2048)) },
	} {
		t.Run(name, func(t *testing.T) {
			p, o := newIdP(t)
			change(p)
			if _, err := o.refresh(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) || len(p.requests) != 1 {
				t.Fatalf("error %v after %d token requests", err, len(p.requests))
			}
		})
	}
}

func TestOIDCLogoutURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", nil)
	redirect := "https://" + host + "/"
	for idToken, want := range map[string]url.Values{
		"id-token": {"id_token_hint": {"id-token"}, "client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
		"":         {"client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
	} {
		u := must(url.Parse(o.logoutURL(idToken, redirect)))
		if u.Scheme+"://"+u.Host+u.Path != issuer+"/api/oidc/end-session" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("ID token %q: %s", idToken, u)
		}
	}
}

func TestParseClaims(t *testing.T) {
	c, err := parseClaims(fakeJWT(map[string]any{"sub": sub, "groups": []string{"a", "b"}, "auth_time": 42}))
	if err != nil || c.Subject != sub || !slices.Equal(c.Groups, []string{"a", "b"}) || c.AuthTime != 42 {
		t.Fatalf("%v %+v", err, c)
	}
	for _, idToken := range []string{"", "a.b", "a.%%%.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[]")) + ".c", "a.b.c.d"} {
		if _, err := parseClaims(idToken); err == nil {
			t.Fatalf("parsed %q", idToken)
		}
	}
}
