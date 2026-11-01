package castelnuovo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const issuer = "https://id.castelnuovo.eu"

var errUnavailable = errors.New("identity provider is unavailable")

type pocketID interface {
	authURL(redirectURL, state, nonce, verifier string) string
	exchange(ctx context.Context, redirectURL, code, verifier string) (tokens, error)
	refresh(ctx context.Context, refreshToken string) (tokens, error)
	logoutURL(idToken, redirectURL string) string
}

type tokens struct {
	idToken, refreshToken string
}

type claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	AMR               []string `json:"amr"`
	AuthTime          int64    `json:"auth_time"`
	Nonce             string   `json:"nonce"`
}

func parseClaims(idToken string) (claims, error) {
	var c claims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return c, errors.New("ID token is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		err = json.Unmarshal(payload, &c)
	}
	return c, err
}

type oidcClient struct {
	issuer   string
	http     *http.Client
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDC(issuer, clientID, secret string, httpClient *http.Client) *oidcClient {
	provider := (&oidc.ProviderConfig{
		IssuerURL:  issuer,
		AuthURL:    issuer + "/authorize",
		TokenURL:   issuer + "/api/oidc/token",
		JWKSURL:    issuer + "/.well-known/jwks.json",
		Algorithms: []string{oidc.RS256},
	}).NewProvider(oidc.ClientContext(context.Background(), httpClient))
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return &oidcClient{
		issuer: issuer,
		http:   httpClient,
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			Endpoint:     endpoint,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups", oidc.ScopeOfflineAccess},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}
}

func (o *oidcClient) authURL(redirectURL, state, nonce, verifier string) string {
	cfg := o.oauth
	cfg.RedirectURL = redirectURL
	return cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(maxAuthAge.Seconds()))),
	)
}

func (o *oidcClient) exchange(ctx context.Context, redirectURL, code, verifier string) (tokens, error) {
	cfg := o.oauth
	cfg.RedirectURL = redirectURL
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return tokens{}, tokenError(err)
	}
	return o.verify(ctx, token)
}

func (o *oidcClient) refresh(ctx context.Context, refreshToken string) (tokens, error) {
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := o.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return tokens{}, tokenError(err)
	}
	return o.verify(ctx, token)
}

func tokenError(err error) error {
	if e, ok := errors.AsType[*oauth2.RetrieveError](err); ok && e.Response != nil && e.Response.StatusCode < 500 && e.Response.StatusCode != http.StatusTooManyRequests {
		return err
	}
	return fmt.Errorf("%w: %w", errUnavailable, err)
}

func (o *oidcClient) verify(ctx context.Context, token *oauth2.Token) (tokens, error) {
	raw, _ := token.Extra("id_token").(string)
	if _, err := o.verifier.Verify(ctx, raw); err != nil {
		if strings.Contains(err.Error(), "fetching keys") {
			return tokens{}, fmt.Errorf("%w: %w", errUnavailable, err)
		}
		return tokens{}, err
	}
	if token.RefreshToken == "" {
		return tokens{}, errors.New("token response has no refresh_token")
	}
	return tokens{raw, token.RefreshToken}, nil
}

func (o *oidcClient) logoutURL(idToken, redirectURL string) string {
	query := url.Values{
		"client_id":                {o.oauth.ClientID},
		"post_logout_redirect_uri": {redirectURL},
	}
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	return o.issuer + "/api/oidc/end-session?" + query.Encode()
}
