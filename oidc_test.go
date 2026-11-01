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
	form                             url.Values
	basicAuthUser, basicAuthPassword string
}

type testIdentityProvider struct {
	signingKey       *rsa.PrivateKey
	forgedSigningKey *rsa.PrivateKey
	claims           map[string]any
	down             bool
	status           int
	jwksStatus       int
	omittedField     string
	requests         []tokenRequest
}

func newTestIdentityProvider(t *testing.T) (*testIdentityProvider, *oidcClient) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testIdentityProvider{signingKey: key, claims: map[string]any{
		"iss":       testIssuer,
		"aud":       "client",
		"sub":       userID,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"nonce":     "nonce",
		"amr":       []string{"phr"},
		"auth_time": time.Now().Unix(),
		"groups":    []string{"admins"},
	}}
	return provider, newOIDCClient(testIssuer, "client", "secret", &http.Client{Transport: provider})
}

func (provider *testIdentityProvider) RoundTrip(request *http.Request) (*http.Response, error) {
	if provider.down {
		return nil, errors.New("connection refused")
	}
	recorder := httptest.NewRecorder()
	switch request.URL.String() {
	case testIssuer + "/.well-known/jwks.json":
		provider.serveKeys(recorder)
	case testIssuer + "/api/oidc/token":
		provider.serveToken(recorder, request)
	default:
		recorder.WriteHeader(http.StatusNotFound)
	}
	return recorder.Result(), nil
}

func (provider *testIdentityProvider) serveKeys(writer http.ResponseWriter) {
	if provider.jwksStatus != 0 {
		writer.WriteHeader(provider.jwksStatus)
		return
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "test",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(provider.signingKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(provider.signingKey.E)).Bytes()),
	}}})
}

func (provider *testIdentityProvider) serveToken(writer http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	user, password, _ := request.BasicAuth()
	provider.requests = append(provider.requests, tokenRequest{request.PostForm, user, password})
	writer.Header().Set("Content-Type", "application/json")
	if provider.status != 0 {
		writer.WriteHeader(provider.status)
		_, _ = writer.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	response := map[string]any{
		"access_token":  "access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      provider.signIDToken(),
		"refresh_token": "new-refresh-token",
	}
	delete(response, provider.omittedField)
	_ = json.NewEncoder(writer).Encode(response)
}

func (provider *testIdentityProvider) signIDToken() string {
	payload, _ := json.Marshal(provider.claims)
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, _ := rsa.SignPKCS1v15(nil, cmp.Or(provider.forgedSigningKey, provider.signingKey), crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCAuthorizationURL(t *testing.T) {
	client := newOIDCClient(issuer, "client", "secret", nil)
	verifier := oauth2.GenerateVerifier()
	location := must(url.Parse(client.authorizationURL("https://"+host+callbackPath, "state", "nonce", verifier)))
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
	if location.Scheme+"://"+location.Host+location.Path != issuer+"/authorize" || !maps.EqualFunc(location.Query(), want, slices.Equal[[]string]) {
		t.Fatalf("%s", location)
	}
}

func TestOIDCExchangeCode(t *testing.T) {
	provider, client := newTestIdentityProvider(t)
	got, err := client.exchangeCode(context.Background(), "https://"+host+callbackPath, "code", "verifier")
	user := got.claims
	if err != nil || got.idToken != provider.signIDToken() || got.refreshToken != "new-refresh-token" || user.Subject != userID || user.Nonce != "nonce" || !slices.Equal(user.AuthenticationMethods, []string{"phr"}) || !slices.Equal(user.Groups, []string{"admins"}) {
		t.Fatalf("%v %+v %+v", err, got, user)
	}

	want := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code"},
		"code_verifier": {"verifier"},
		"redirect_uri":  {"https://" + host + callbackPath},
	}
	if len(provider.requests) != 1 || provider.requests[0].basicAuthUser != "client" || provider.requests[0].basicAuthPassword != "secret" || !maps.EqualFunc(provider.requests[0].form, want, slices.Equal[[]string]) {
		t.Fatalf("token requests: %+v", provider.requests)
	}
}

func TestOIDCExchangeCodeFails(t *testing.T) {
	tests := map[string]struct {
		change      func(*testIdentityProvider)
		requests    int
		unavailable bool
	}{
		"code rejected":    {func(provider *testIdentityProvider) { provider.status = http.StatusBadRequest }, 1, false},
		"server error":     {func(provider *testIdentityProvider) { provider.status = http.StatusServiceUnavailable }, 1, true},
		"rate limited":     {func(provider *testIdentityProvider) { provider.status = http.StatusTooManyRequests }, 1, true},
		"unreachable":      {func(provider *testIdentityProvider) { provider.down = true }, 0, true},
		"no ID token":      {func(provider *testIdentityProvider) { provider.omittedField = "id_token" }, 1, false},
		"no refresh token": {func(provider *testIdentityProvider) { provider.omittedField = "refresh_token" }, 1, false},
		"another audience": {func(provider *testIdentityProvider) { provider.claims["aud"] = "other" }, 1, false},
		"another issuer":   {func(provider *testIdentityProvider) { provider.claims["iss"] = "https://evil.example" }, 1, false},
		"expired ID token": {func(provider *testIdentityProvider) { provider.claims["exp"] = time.Now().Add(-time.Hour).Unix() }, 1, false},
		"another signer": {func(provider *testIdentityProvider) {
			provider.forgedSigningKey = must(rsa.GenerateKey(rand.Reader, 2048))
		}, 1, false},
		"keys unavailable": {func(provider *testIdentityProvider) { provider.jwksStatus = http.StatusServiceUnavailable }, 1, true},
		"malformed claims": {func(provider *testIdentityProvider) { provider.claims["auth_time"] = "yesterday" }, 1, false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			provider, client := newTestIdentityProvider(t)
			test.change(provider)
			_, err := client.exchangeCode(context.Background(), "https://"+host+callbackPath, "code", "verifier")
			if err == nil || errors.Is(err, errUnavailable) != test.unavailable || len(provider.requests) != test.requests {
				t.Fatalf("error %v after %d token requests", err, len(provider.requests))
			}
		})
	}
}

func TestOIDCRefreshTokens(t *testing.T) {
	provider, client := newTestIdentityProvider(t)
	got, err := client.refreshTokens(context.Background(), "old-refresh-token")
	if err != nil || got.claims.Subject != userID || got.idToken != provider.signIDToken() || got.refreshToken != "new-refresh-token" {
		t.Fatalf("%v %+v", err, got)
	}
	want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"old-refresh-token"}}
	if len(provider.requests) != 1 || provider.requests[0].basicAuthUser != "client" || provider.requests[0].basicAuthPassword != "secret" || !maps.EqualFunc(provider.requests[0].form, want, slices.Equal[[]string]) {
		t.Fatalf("token requests: %+v", provider.requests)
	}

	provider.status = http.StatusBadRequest
	if _, err := client.refreshTokens(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) {
		t.Fatalf("rejected refresh token: %v", err)
	}
	provider.status = http.StatusBadGateway
	if _, err := client.refreshTokens(context.Background(), "old-refresh-token"); !errors.Is(err, errUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

func TestOIDCRefreshVerifiesIDToken(t *testing.T) {
	for name, change := range map[string]func(*testIdentityProvider){
		"no ID token":      func(provider *testIdentityProvider) { provider.omittedField = "id_token" },
		"another audience": func(provider *testIdentityProvider) { provider.claims["aud"] = "other" },
		"another issuer":   func(provider *testIdentityProvider) { provider.claims["iss"] = "https://evil.example" },
		"expired ID token": func(provider *testIdentityProvider) { provider.claims["exp"] = time.Now().Add(-time.Hour).Unix() },
		"another signer": func(provider *testIdentityProvider) {
			provider.forgedSigningKey = must(rsa.GenerateKey(rand.Reader, 2048))
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider, client := newTestIdentityProvider(t)
			change(provider)
			if _, err := client.refreshTokens(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) || len(provider.requests) != 1 {
				t.Fatalf("error %v after %d token requests", err, len(provider.requests))
			}
		})
	}
}

func TestOIDCLogoutURL(t *testing.T) {
	client := newOIDCClient(issuer, "client", "secret", nil)
	redirect := "https://" + host + "/"
	for idToken, want := range map[string]url.Values{
		"id-token": {"id_token_hint": {"id-token"}, "client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
		"":         {"client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
	} {
		location := must(url.Parse(client.logoutURL(idToken, redirect)))
		if location.Scheme+"://"+location.Host+location.Path != issuer+"/api/oidc/end-session" || !maps.EqualFunc(location.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("ID token %q: %s", idToken, location)
		}
	}
}
