package castelnuovo

import (
	"bytes"
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
	retryInterval   = 10 * time.Second
	sessionLifetime = 12 * time.Hour
	loginTimeout    = 10 * time.Minute

	sessionCookie    = "__Host-castelnuovo"
	loginCookie      = "__Host-castelnuovo-login-"
	maxCookieSize    = 4096
	maxPendingLogins = 3

	loginPath    = "/.castelnuovo/login"
	callbackPath = "/.castelnuovo/callback"
	logoutPath   = "/.castelnuovo/logout"
)

var (
	certificateURI = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	crossOrigin    = http.NewCrossOriginProtection()

	errUnavailable = errors.New("identity provider is unavailable")
	errLoginTooOld = errors.New("login is too old")
)

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
	mu             sync.Mutex
	host, uri, sub string
	claims         *claims
	refreshToken   string
	refreshedAt    time.Time
	failedAt       time.Time
	expiresAt      time.Time
}

type pendingLogin struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
	Reauth   bool   `json:"reauth,omitempty"`
}

type pocketID interface {
	authURL(redirectURL, state, nonce, verifier string, reauth bool) string
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
	sessionID, logins := removeCookies(r)

	uri, err := m.certificate(r)
	if err != nil {
		return m.deny(r, http.StatusForbidden, err, "", uri)
	}

	switch path := original(r).Path; {
	case path == loginPath && r.Method == http.MethodGet:
		m.login(w, r, logins, original(r).Query().Get("rd"), false)
		return nil
	case path == callbackPath && r.Method == http.MethodGet:
		return m.callback(w, r, uri, sessionID, logins)
	case path == logoutPath && r.Method == http.MethodPost:
		return m.logout(w, r, uri, sessionID)
	case path == loginPath || path == callbackPath:
		w.Header().Set("Allow", http.MethodGet)
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts GET", path))
	case path == logoutPath:
		w.Header().Set("Allow", http.MethodPost)
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts POST", path))
	}

	c, err := m.verify(r, uri, sessionID)
	switch {
	case err != nil:
		return err
	case c == nil:
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
	case certificateOwner(uri) == "":
		return uri, errors.New("client certificate is not allowed")
	}
	return uri, nil
}

func certificateOwner(uri string) string {
	if match := certificateURI.FindStringSubmatch(uri); match != nil {
		return match[1]
	}
	return ""
}

func (m *Auth) verify(r *http.Request, uri, id string) (*claims, error) {
	sess := m.store.get(id)
	switch {
	case sess == nil || !m.now().Before(sess.expiresAt):
		return nil, nil
	case sess.host != r.Host || sess.uri != uri:
		m.log.Warn("session used from another host or certificate", append(logFields(r, sess.sub, uri), zap.String("session_host", sess.host), zap.String("session_certificate", sess.uri))...)
		return nil, nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if m.store.get(id) != sess {
		return nil, nil
	}
	err := m.refresh(context.WithoutCancel(r.Context()), sess)
	switch {
	case errors.Is(err, errUnavailable):
		return nil, m.deny(r, http.StatusBadGateway, err, sess.sub, uri)
	case err != nil:
		m.store.remove(id)
		m.log.Warn("session ended", append(logFields(r, sess.sub, uri), zap.Error(err))...)
		return nil, nil
	}
	return sess.claims, nil
}

func (m *Auth) refresh(ctx context.Context, sess *session) error {
	if m.now().Sub(sess.refreshedAt) < refreshInterval {
		return nil
	}
	if m.now().Sub(sess.failedAt) < retryInterval {
		return errUnavailable
	}
	c, refreshToken, err := m.idp.refresh(ctx, sess.refreshToken)
	switch {
	case errors.Is(err, errUnavailable):
		sess.failedAt = m.now()
		return err
	case err != nil:
		return err
	case c.Subject != sess.sub:
		return errors.New("refresh returned another user")
	}
	sess.claims, sess.refreshToken, sess.refreshedAt = c, refreshToken, m.now()
	return nil
}

func challenge(w http.ResponseWriter, r *http.Request) error {
	if mode := r.Header.Get("Sec-Fetch-Mode"); r.Method != http.MethodGet || (mode != "" && mode != "navigate") {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(w, r, loginPath+"?rd="+url.QueryEscape(original(r).RequestURI()), http.StatusFound)
	return nil
}

func (m *Auth) login(w http.ResponseWriter, r *http.Request, pending map[string]string, redirect string, reauth bool) {
	if len(pending) >= maxPendingLogins {
		for state := range pending {
			setCookie(w, loginCookie+state, "", -time.Second)
		}
	}
	l := pendingLogin{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Redirect: redirect,
		Reauth:   reauth,
	}
	value := encodeLogin(l)
	if len(loginCookie)+len(l.State)+len(value) > maxCookieSize {
		l.Redirect = ""
		value = encodeLogin(l)
	}
	setCookie(w, loginCookie+l.State, value, loginTimeout)
	http.Redirect(w, r, m.idp.authURL(callbackURL(r.Host), l.State, l.Nonce, l.Verifier, reauth), http.StatusFound)
}

func encodeLogin(l pendingLogin) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(l)
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func (m *Auth) callback(w http.ResponseWriter, r *http.Request, uri, sessionID string, logins map[string]string) error {
	query := original(r).Query()
	state := query.Get("state")
	login, ok := logins[state]
	if !ok || state == "" {
		if c, err := m.verify(r, uri, sessionID); c != nil && err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return nil
		}
		return m.deny(r, http.StatusBadRequest, errors.New("login cookie is missing"), "", uri)
	}
	delete(logins, state)
	setCookie(w, loginCookie+state, "", -time.Second)

	var l pendingLogin
	value, err := base64.RawURLEncoding.DecodeString(login)
	if err == nil {
		err = json.Unmarshal(value, &l)
	}
	switch {
	case err != nil || l.State != state:
		return m.deny(r, http.StatusBadRequest, errors.New("login cookie is invalid"), "", uri)
	case query.Get("code") == "":
		return m.deny(r, http.StatusForbidden, errors.New("identity provider returned an error"), "", uri, zap.String("idp_error", query.Get("error")))
	}

	c, refreshToken, err := m.idp.exchange(r.Context(), callbackURL(r.Host), query.Get("code"), l.Verifier)
	if err == nil {
		err = m.checkLogin(c, l.Nonce, uri)
	}
	switch {
	case errors.Is(err, errUnavailable):
		return m.deny(r, http.StatusBadGateway, err, "", uri)
	case errors.Is(err, errLoginTooOld) && !l.Reauth:
		m.log.Info("asking for a new login", append(logFields(r, c.Subject, uri), zap.Error(err))...)
		m.login(w, r, logins, l.Redirect, true)
		return nil
	case err != nil:
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
		sub:          c.Subject,
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
	case uri != "" && certificateOwner(uri) != c.Subject:
		return errors.New("client certificate belongs to another user")
	case !slices.Contains(c.AMR, "phr"):
		return errors.New("login did not use a passkey")
	case m.now().Sub(time.Unix(c.AuthTime, 0)) > maxAuthAge:
		return errLoginTooOld
	}
	return nil
}

func (m *Auth) logout(w http.ResponseWriter, r *http.Request, uri, id string) error {
	if err := crossOrigin.Check(r); err != nil {
		return m.deny(r, http.StatusForbidden, err, "", uri)
	}
	var idToken string
	if sess := m.store.get(id); sess != nil {
		m.store.remove(id)
		m.log.Info("user logged out", logFields(r, sess.sub, sess.uri)...)
		sess.mu.Lock()
		idToken = sess.claims.idToken
		sess.mu.Unlock()
	}
	setCookie(w, sessionCookie, "", -time.Second)
	http.Redirect(w, r, m.idp.logoutURL(idToken, "https://"+r.Host+"/"), http.StatusSeeOther)
	return nil
}

func (m *Auth) deny(r *http.Request, status int, err error, sub, uri string, fields ...zap.Field) error {
	fields = append(append(logFields(r, sub, uri), fields...), zap.String("path", original(r).Path), zap.Error(err))
	m.log.Warn("request denied", fields...)
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
	if clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); clientIP != "" {
		fields = append(fields, zap.String("client_ip", clientIP))
	}
	return fields
}

func original(r *http.Request) *url.URL {
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		return orig.URL
	}
	return r.URL
}

func removeCookies(r *http.Request) (sessionID string, logins map[string]string) {
	logins = map[string]string{}
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookie:
				sessionID = value
			case strings.HasPrefix(name, loginCookie):
				logins[strings.TrimPrefix(name, loginCookie)] = value
			case strings.HasPrefix(name, sessionCookie):
			case part != "":
				kept = append(kept, part)
			}
		}
	}
	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return sessionID, logins
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
