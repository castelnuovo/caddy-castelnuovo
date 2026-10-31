package castelnuovo

import (
	"context"
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

type claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	AMR               []string `json:"amr"`
	AuthTime          int64    `json:"auth_time"`
	Nonce             string   `json:"nonce"`
	idToken           string
}

type pocketID interface {
	authURL(redirectURL, state, nonce, verifier string, reauth bool) string
	exchange(ctx context.Context, redirectURL, code, verifier string) (*claims, string, error)
	refresh(ctx context.Context, refreshToken string) (*claims, string, error)
	logoutURL(idToken, redirectURL string) string
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

func (o *oidcClient) authURL(redirectURL, state, nonce, verifier string, reauth bool) string {
	cfg := o.oauth
	cfg.RedirectURL = redirectURL
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(maxAuthAge.Seconds()))),
	}
	if reauth {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	return cfg.AuthCodeURL(state, opts...)
}

func (o *oidcClient) exchange(ctx context.Context, redirectURL, code, verifier string) (*claims, string, error) {
	cfg := o.oauth
	cfg.RedirectURL = redirectURL
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, "", tokenError(err)
	}
	return o.claims(ctx, token)
}

func (o *oidcClient) refresh(ctx context.Context, refreshToken string) (*claims, string, error) {
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := o.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, "", tokenError(err)
	}
	return o.claims(ctx, token)
}

func tokenError(err error) error {
	e, ok := errors.AsType[*oauth2.RetrieveError](err)
	if !ok || e.Response != nil && (e.Response.StatusCode >= 500 || e.Response.StatusCode == http.StatusTooManyRequests) {
		return fmt.Errorf("%w: %w", errUnavailable, err)
	}
	return err
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

func (o *oidcClient) claims(ctx context.Context, token *oauth2.Token) (*claims, string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("token response has no id_token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil && strings.Contains(err.Error(), "fetching keys") {
		return nil, "", fmt.Errorf("%w: %w", errUnavailable, err)
	}
	if err != nil {
		return nil, "", err
	}
	var c claims
	if err := idToken.Claims(&c); err != nil {
		return nil, "", err
	}
	if token.RefreshToken == "" {
		return nil, "", errors.New("token response has no refresh_token")
	}
	c.idToken = raw
	return &c, token.RefreshToken, nil
}
