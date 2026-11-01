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
	authorizationURL(redirectURL, state, nonce, codeVerifier string) string
	exchangeCode(ctx context.Context, redirectURL, code, codeVerifier string) (tokenResponse, error)
	verifyIDToken(ctx context.Context, idToken string) (claims, error)
	refreshTokens(ctx context.Context, refreshToken string) (tokenResponse, error)
	endSession(ctx context.Context, idToken string) error
	logoutURL(idToken, redirectURL string) string
}

type tokenResponse struct {
	idToken, refreshToken string
	claims                claims
}

type claims struct {
	Subject               string   `json:"sub"`
	PreferredUsername     string   `json:"preferred_username"`
	Name                  string   `json:"name"`
	Email                 string   `json:"email"`
	Groups                []string `json:"groups"`
	AuthenticationMethods []string `json:"amr"`
	AuthenticatedAt       int64    `json:"auth_time"`
	Nonce                 string   `json:"nonce"`
}

func parseUnverifiedClaims(idToken string) (claims, error) {
	var parsed claims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return parsed, errors.New("ID token is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		err = json.Unmarshal(payload, &parsed)
	}
	return parsed, err
}

type oidcClient struct {
	issuer          string
	httpClient      *http.Client
	oauthConfig     oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
}

func newOIDCClient(issuer, clientID, secret string, httpClient *http.Client) *oidcClient {
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
		issuer:     issuer,
		httpClient: httpClient,
		oauthConfig: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			Endpoint:     endpoint,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups", oidc.ScopeOfflineAccess},
		},
		idTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}
}

func (client *oidcClient) authorizationURL(redirectURL, state, nonce, codeVerifier string) string {
	config := client.oauthConfig
	config.RedirectURL = redirectURL
	return config.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(int(maxAuthenticationAge.Seconds()))),
	)
}

func (client *oidcClient) exchangeCode(ctx context.Context, redirectURL, code, codeVerifier string) (tokenResponse, error) {
	config := client.oauthConfig
	config.RedirectURL = redirectURL
	ctx = oidc.ClientContext(ctx, client.httpClient)
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return tokenResponse{}, classifyTokenError(err)
	}
	return client.verifyTokenResponse(ctx, token)
}

func classifyTokenError(err error) error {
	if retrieveError, ok := errors.AsType[*oauth2.RetrieveError](err); ok && retrieveError.Response != nil && retrieveError.Response.StatusCode < 500 && retrieveError.Response.StatusCode != http.StatusTooManyRequests {
		return err
	}
	return fmt.Errorf("%w: %w", errUnavailable, err)
}

func (client *oidcClient) verifyTokenResponse(ctx context.Context, token *oauth2.Token) (tokenResponse, error) {
	rawIDToken, _ := token.Extra("id_token").(string)
	verifiedClaims, err := client.verifyIDToken(ctx, rawIDToken)
	switch {
	case err != nil:
		return tokenResponse{}, err
	case token.RefreshToken == "":
		return tokenResponse{}, errors.New("token response has no refresh_token")
	}
	return tokenResponse{rawIDToken, token.RefreshToken, verifiedClaims}, nil
}

func (client *oidcClient) verifyIDToken(ctx context.Context, idToken string) (claims, error) {
	var verifiedClaims claims
	parsedToken, err := client.idTokenVerifier.Verify(oidc.ClientContext(ctx, client.httpClient), idToken)
	switch {
	case err != nil && strings.Contains(err.Error(), "fetching keys"):
		return verifiedClaims, fmt.Errorf("%w: %w", errUnavailable, err)
	case err != nil:
		return verifiedClaims, err
	}
	return verifiedClaims, parsedToken.Claims(&verifiedClaims)
}

func (client *oidcClient) refreshTokens(ctx context.Context, refreshToken string) (tokenResponse, error) {
	ctx = oidc.ClientContext(ctx, client.httpClient)
	token, err := client.oauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return tokenResponse{}, classifyTokenError(err)
	}
	return client.verifyTokenResponse(ctx, token)
}

func (client *oidcClient) endSession(ctx context.Context, idToken string) error {
	form := url.Values{"client_id": {client.oauthConfig.ClientID}, "id_token_hint": {idToken}}
	endSessionRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.issuer+"/api/oidc/end-session", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	endSessionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withoutRedirects := *client.httpClient
	withoutRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := withoutRedirects.Do(endSessionRequest)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") == client.issuer+"/logout" {
		return fmt.Errorf("identity provider did not end the session: %s to %q", response.Status, response.Header.Get("Location"))
	}
	return nil
}

func (client *oidcClient) logoutURL(idToken, redirectURL string) string {
	query := url.Values{
		"client_id":                {client.oauthConfig.ClientID},
		"post_logout_redirect_uri": {redirectURL},
	}
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	return client.issuer + "/api/oidc/end-session?" + query.Encode()
}
