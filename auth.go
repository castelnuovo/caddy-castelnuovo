package castelnuovo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	issuer = "https://id.castelnuovo.eu"

	maxAuthAge      = time.Hour
	refreshInterval = 5 * time.Minute
	sessionLifetime = 12 * time.Hour
	loginTimeout    = 10 * time.Minute

	sessionCookie = "__Host-castelnuovo"
	loginCookie   = "__Host-castelnuovo-login"

	loginPath    = "/.castelnuovo/login"
	callbackPath = "/.castelnuovo/callback"
	logoutPath   = "/.castelnuovo/logout"
)

var certificateURI = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

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

type session struct {
	mu           sync.Mutex
	host, uri    string
	claims       *claims
	refreshToken string
	refreshedAt  time.Time
	expiresAt    time.Time
}

type pendingLogin struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
}

type pocketID interface {
	authURL(redirectURL, state, nonce, verifier string) string
	exchange(ctx context.Context, redirectURL, code, verifier string) (*claims, string, error)
	refresh(ctx context.Context, refreshToken string) (*claims, string, error)
	logoutURL(idToken, redirectURL string) string
}

type store struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newStore() *store {
	return &store{sessions: map[string]*session{}}
}

func (*store) Destruct() error { return nil }

func (s *store) get(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

func (s *store) add(sess *session, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.sessions {
		if !now.Before(existing.expiresAt) {
			delete(s.sessions, id)
		}
	}
	id := rand.Text()
	s.sessions[id] = sess
	return id
}

func (s *store) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (m *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(r.Header, name)
		}
	}
	sessionID, login := removeCookies(r)

	uri, err := m.certificate(r)
	if err != nil {
		return m.deny(r, http.StatusForbidden, err, "", uri)
	}

	switch path := original(r).Path; {
	case path == loginPath && r.Method == http.MethodGet:
		m.login(w, r)
		return nil
	case path == callbackPath && r.Method == http.MethodGet:
		return m.callback(w, r, uri, login)
	case path == logoutPath && r.Method == http.MethodPost:
		return m.logout(w, r, uri, sessionID)
	case path == loginPath || path == callbackPath:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts GET", path))
	case path == logoutPath:
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts POST", path))
	}

	c := m.verify(r, uri, sessionID)
	if c == nil {
		return challenge(w, r)
	}
	r.Header.Set("X-Auth-Sub", c.Subject)
	r.Header.Set("X-Auth-User", c.PreferredUsername)
	r.Header.Set("X-Auth-Name", c.Name)
	r.Header.Set("X-Auth-Email", c.Email)
	r.Header.Set("X-Auth-Groups", strings.Join(c.Groups, ","))
	return next.ServeHTTP(w, r)
}

func (m *Auth) certificate(r *http.Request) (string, error) {
	if m.DisableClientCertificate {
		return "", nil
	}
	var uri string
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0][0].URIs) > 0 {
		uri = r.TLS.VerifiedChains[0][0].URIs[0].String()
	}
	switch {
	case uri == "":
		return "", errors.New("a client certificate is required")
	case !certificateURI.MatchString(uri):
		return uri, errors.New("client certificate is not allowed")
	}
	return uri, nil
}

func (m *Auth) verify(r *http.Request, uri, id string) *claims {
	sess := m.store.get(id)
	if sess == nil || sess.host != r.Host || sess.uri != uri || !m.now().Before(sess.expiresAt) {
		return nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if m.store.get(id) != sess {
		return nil
	}
	if err := m.refresh(context.WithoutCancel(r.Context()), sess); err != nil {
		m.store.remove(id)
		m.log.Warn("session ended", append(logFields(r, sess.claims.Subject, uri), zap.Error(err))...)
		return nil
	}
	return sess.claims
}

func (m *Auth) refresh(ctx context.Context, sess *session) error {
	if m.now().Sub(sess.refreshedAt) < refreshInterval {
		return nil
	}
	c, refreshToken, err := m.idp.refresh(ctx, sess.refreshToken)
	if err != nil {
		return err
	}
	if c.Subject != sess.claims.Subject {
		return errors.New("refresh returned another user")
	}
	sess.claims, sess.refreshToken, sess.refreshedAt = c, refreshToken, m.now()
	return nil
}

func challenge(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(w, r, loginPath+"?rd="+url.QueryEscape(original(r).RequestURI()), http.StatusFound)
	return nil
}

func (m *Auth) login(w http.ResponseWriter, r *http.Request) {
	l := pendingLogin{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Redirect: original(r).Query().Get("rd"),
	}
	value, _ := json.Marshal(l)
	setCookie(w, loginCookie, base64.RawURLEncoding.EncodeToString(value), loginTimeout)
	http.Redirect(w, r, m.idp.authURL(callbackURL(r.Host), l.State, l.Nonce, l.Verifier), http.StatusFound)
}

func (m *Auth) callback(w http.ResponseWriter, r *http.Request, uri, login string) error {
	var l pendingLogin
	value, err := base64.RawURLEncoding.DecodeString(login)
	if err == nil {
		err = json.Unmarshal(value, &l)
	}
	query := original(r).Query()
	switch {
	case login == "":
		return m.deny(r, http.StatusBadRequest, errors.New("login cookie is missing"), "", uri)
	case err != nil || l.State == "":
		return m.deny(r, http.StatusBadRequest, errors.New("login cookie is invalid"), "", uri)
	case l.State != query.Get("state"):
		return m.deny(r, http.StatusBadRequest, errors.New("state does not match the login cookie"), "", uri)
	}
	setCookie(w, loginCookie, "", -time.Second)

	c, refreshToken, err := m.idp.exchange(r.Context(), callbackURL(r.Host), query.Get("code"), l.Verifier)
	if err == nil {
		err = m.checkLogin(c, l.Nonce, uri)
	}
	if err != nil {
		var sub string
		if c != nil {
			sub = c.Subject
		}
		return m.deny(r, http.StatusForbidden, err, sub, uri)
	}

	now := m.now()
	id := m.store.add(&session{
		host:         r.Host,
		uri:          uri,
		claims:       c,
		refreshToken: refreshToken,
		refreshedAt:  now,
		expiresAt:    now.Add(sessionLifetime),
	}, now)

	m.log.Info("user logged in", logFields(r, c.Subject, uri)...)
	setCookie(w, sessionCookie, id, sessionLifetime)
	if !isLocalPath(l.Redirect) {
		l.Redirect = "/"
	}
	http.Redirect(w, r, l.Redirect, http.StatusFound)
	return nil
}

func (m *Auth) checkLogin(c *claims, nonce, uri string) error {
	switch {
	case c.Subject == "":
		return errors.New("ID token has no subject")
	case c.Nonce != nonce:
		return errors.New("ID token nonce does not match")
	case !slices.Contains(c.AMR, "phr"):
		return errors.New("login did not use a passkey")
	case m.now().Sub(time.Unix(c.AuthTime, 0)) > maxAuthAge:
		return errors.New("login is too old")
	case uri != "" && certificateURI.FindStringSubmatch(uri)[1] != c.Subject:
		return errors.New("client certificate belongs to another user")
	}
	return nil
}

func (m *Auth) logout(w http.ResponseWriter, r *http.Request, uri, id string) error {
	if err := http.NewCrossOriginProtection().Check(r); err != nil {
		return m.deny(r, http.StatusForbidden, err, "", uri)
	}
	var idToken string
	if sess := m.store.get(id); sess != nil {
		m.store.remove(id)
		sess.mu.Lock()
		idToken = sess.claims.idToken
		m.log.Info("user logged out", logFields(r, sess.claims.Subject, sess.uri)...)
		sess.mu.Unlock()
	}
	setCookie(w, sessionCookie, "", -time.Second)
	http.Redirect(w, r, m.idp.logoutURL(idToken, "https://"+r.Host+"/"), http.StatusSeeOther)
	return nil
}

func (m *Auth) deny(r *http.Request, status int, err error, sub, uri string) error {
	clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	m.log.Warn("request denied", append(logFields(r, sub, uri), zap.String("path", original(r).Path), zap.String("client_ip", clientIP), zap.Error(err))...)
	return caddyhttp.Error(status, err)
}

func logFields(r *http.Request, sub, uri string) []zap.Field {
	var fields []zap.Field
	if sub != "" {
		fields = append(fields, zap.String("sub", sub))
	}
	fields = append(fields, zap.String("host", r.Host))
	if uri != "" {
		fields = append(fields, zap.String("certificate", uri))
	}
	return fields
}

func original(r *http.Request) *url.URL {
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		return orig.URL
	}
	return r.URL
}

func removeCookies(r *http.Request) (sessionID, login string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		switch c.Name {
		case sessionCookie:
			sessionID = c.Value
		case loginCookie:
			login = c.Value
		default:
			r.AddCookie(c)
		}
	}
	return sessionID, login
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, `\`) && !strings.ContainsFunc(p, unicode.IsControl)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

type oidcClient struct {
	http     *http.Client
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDC(clientID, secret string) *oidcClient {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	provider := (&oidc.ProviderConfig{
		IssuerURL:  issuer,
		AuthURL:    issuer + "/authorize",
		TokenURL:   issuer + "/api/oidc/token",
		JWKSURL:    issuer + "/.well-known/jwks.json",
		Algorithms: []string{oidc.RS256},
	}).NewProvider(oidc.ClientContext(context.Background(), httpClient))
	return &oidcClient{
		http: httpClient,
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: secret,
			Endpoint:     provider.Endpoint(),
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

func (o *oidcClient) exchange(ctx context.Context, redirectURL, code, verifier string) (*claims, string, error) {
	cfg := o.oauth
	cfg.RedirectURL = redirectURL
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, "", err
	}
	return o.claims(ctx, token)
}

func (o *oidcClient) refresh(ctx context.Context, refreshToken string) (*claims, string, error) {
	ctx = oidc.ClientContext(ctx, o.http)
	token, err := o.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, "", err
	}
	return o.claims(ctx, token)
}

func (o *oidcClient) logoutURL(idToken, redirectURL string) string {
	return issuer + "/api/oidc/end-session?" + url.Values{
		"id_token_hint":            {idToken},
		"client_id":                {o.oauth.ClientID},
		"post_logout_redirect_uri": {redirectURL},
	}.Encode()
}

func (o *oidcClient) claims(ctx context.Context, token *oauth2.Token) (*claims, string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", errors.New("token response has no id_token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
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
