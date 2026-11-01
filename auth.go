package castelnuovo

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	loginPath    = "/.castelnuovo/login"
	callbackPath = "/.castelnuovo/callback"
	logoutPath   = "/.castelnuovo/logout"

	sessionCookie = "__Host-castelnuovo"
	loginCookie   = "__Host-castelnuovo-login-"
	maxCookieSize = 4096

	sessionLifetime  = 12 * time.Hour
	refreshInterval  = 5 * time.Minute
	maxAuthAge       = time.Hour
	loginTimeout     = 10 * time.Minute
	maxPendingLogins = 3
)

var (
	yubikeyURI        = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	crossOrigin       = http.NewCrossOriginProtection()
	errCookieTooLarge = errors.New("cookie is larger than 4096 bytes")
)

type request struct {
	w       http.ResponseWriter
	r       *http.Request
	orig    *http.Request
	cert    string
	session string
	logins  map[string]string
	log     *zap.Logger
}

type session struct {
	IDToken      string `json:"i"`
	RefreshToken string `json:"r"`
	RefreshedAt  int64  `json:"f"`
	ExpiresAt    int64  `json:"x"`
	Host         string `json:"h"`
	Certificate  string `json:"c,omitempty"`
}

type pendingLogin struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r,omitempty"`
}

type refreshed struct {
	cookie *http.Cookie
	claims claims
}

func (m *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	removeAuthHeaders(r)
	req := m.newRequest(w, r)
	if !m.DisableClientCertificate && certificateOwner(req.cert) == "" {
		return req.deny(http.StatusForbidden, errors.New("a client certificate of a user is required"))
	}

	switch path, method := req.orig.URL.Path, req.orig.Method; {
	case path == loginPath && method == http.MethodGet:
		return m.login(req)
	case path == callbackPath && method == http.MethodGet:
		return m.callback(req)
	case path == logoutPath && method == http.MethodPost:
		return m.logout(req)
	case path == loginPath || path == callbackPath:
		return methodNotAllowed(w, path, http.MethodGet)
	case path == logoutPath:
		return methodNotAllowed(w, path, http.MethodPost)
	}

	c, err := m.authenticate(req)
	switch {
	case err != nil:
		return err
	case c == nil:
		return challenge(req)
	}
	r.Header.Set("X-Auth-Sub", c.Subject)
	r.Header.Set("X-Auth-User", c.PreferredUsername)
	r.Header.Set("X-Auth-Name", c.Name)
	r.Header.Set("X-Auth-Email", c.Email)
	r.Header.Set("X-Auth-Groups", strings.Join(c.Groups, ","))
	return next.ServeHTTP(w, r)
}

func (m *Auth) newRequest(w http.ResponseWriter, r *http.Request) *request {
	req := &request{w: w, r: r, orig: r}
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		req.orig = &orig
	}
	req.session, req.logins = takeCookies(r)
	if !m.DisableClientCertificate {
		req.cert = clientCertificate(r)
	}

	fields := []zap.Field{zap.String("host", r.Host)}
	if req.cert != "" {
		fields = append(fields, zap.String("certificate", req.cert))
	}
	if clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); clientIP != "" {
		fields = append(fields, zap.String("client_ip", clientIP))
	}
	req.log = m.log.WithLazy(fields...)
	return req
}

func (req *request) deny(status int, err error, fields ...zap.Field) error {
	req.log.Warn("request denied", append(fields, zap.String("path", req.orig.URL.Path), zap.Error(err))...)
	return caddyhttp.Error(status, err)
}

func challenge(req *request) error {
	mode, dest := req.r.Header.Get("Sec-Fetch-Mode"), req.r.Header.Get("Sec-Fetch-Dest")
	if req.orig.Method != http.MethodGet || mode != "" && mode != "navigate" || dest != "" && dest != "document" {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(req.w, req.r, loginPath+"?rd="+url.QueryEscape(req.orig.URL.RequestURI()), http.StatusFound)
	return nil
}

func methodNotAllowed(w http.ResponseWriter, path, allow string) error {
	w.Header().Set("Allow", allow)
	return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts %s", path, allow))
}

func (m *Auth) authenticate(req *request) (*claims, error) {
	now := m.now().Unix()
	s, sub, ok := m.openSession(req)
	switch {
	case !ok || now >= s.ExpiresAt:
		return nil, nil
	case s.Host != req.r.Host || s.Certificate != req.cert:
		req.log.Warn("session used from another host or certificate", zap.String("sub", sub), zap.String("session_host", s.Host), zap.String("session_certificate", s.Certificate))
		return nil, nil
	}
	ctx := context.WithoutCancel(req.r.Context())
	if now-s.RefreshedAt < int64(refreshInterval.Seconds()) {
		if verified, err := m.idp.verifyIDToken(ctx, s.IDToken); err == nil {
			return &verified, nil
		}
	}

	v, err, _ := m.refreshes.Do(s.RefreshToken, func() (any, error) {
		return m.refresh(ctx, s, sub)
	})
	switch {
	case errors.Is(err, errUnavailable):
		return nil, req.deny(http.StatusBadGateway, err, zap.String("sub", sub))
	case err != nil:
		expire(req.w, sessionCookie)
		req.log.Warn("session ended", zap.String("sub", sub), zap.Error(err))
		return nil, nil
	}
	r := v.(refreshed)
	http.SetCookie(req.w, r.cookie)
	return &r.claims, nil
}

func (m *Auth) refresh(ctx context.Context, s session, sub string) (refreshed, error) {
	t, err := m.idp.refresh(ctx, s.RefreshToken)
	switch {
	case err != nil:
		return refreshed{}, err
	case t.claims.Subject != sub:
		return refreshed{}, errors.New("refresh returned another user")
	}
	now := m.now().Unix()
	if now >= s.ExpiresAt {
		return refreshed{}, errors.New("session expired during the refresh")
	}
	s.IDToken, s.RefreshToken, s.RefreshedAt = t.idToken, t.refreshToken, now
	cookie, err := m.sealSession(s)
	return refreshed{cookie, t.claims}, err
}

func (m *Auth) openSession(req *request) (s session, sub string, ok bool) {
	if m.open(sessionCookie, req.session, &s) != nil {
		return session{}, "", false
	}
	c, err := parseClaims(s.IDToken)
	return s, c.Subject, err == nil
}

func (m *Auth) sealSession(s session) (*http.Cookie, error) {
	return m.seal(sessionCookie, s, int(s.ExpiresAt-s.RefreshedAt))
}

func (m *Auth) login(req *request) error {
	if len(req.logins) >= maxPendingLogins {
		for state := range req.logins {
			expire(req.w, loginCookie+state)
		}
	}
	state := rand.Text()
	l := pendingLogin{Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(), Redirect: req.orig.URL.Query().Get("rd")}
	c, err := m.seal(loginCookie+state, l, int(loginTimeout.Seconds()))
	if errors.Is(err, errCookieTooLarge) {
		l.Redirect = ""
		c, err = m.seal(loginCookie+state, l, int(loginTimeout.Seconds()))
	}
	if err != nil {
		return err
	}
	http.SetCookie(req.w, c)
	http.Redirect(req.w, req.r, m.idp.authURL(callbackURL(req.r.Host), state, l.Nonce, l.Verifier), http.StatusFound)
	return nil
}

func (m *Auth) callback(req *request) error {
	query := req.orig.URL.Query()
	state := query.Get("state")
	value, ok := req.logins[state]
	if !ok {
		return req.deny(http.StatusBadRequest, errors.New("callback without a pending login"))
	}
	expire(req.w, loginCookie+state)
	var l pendingLogin
	if err := m.open(loginCookie+state, value, &l); err != nil {
		return req.deny(http.StatusBadRequest, errors.New("login cookie is invalid"))
	}
	if query.Get("code") == "" {
		return req.deny(http.StatusForbidden, errors.New("identity provider returned an error"), zap.String("idp_error", query.Get("error")))
	}

	t, err := m.idp.exchange(req.r.Context(), callbackURL(req.r.Host), query.Get("code"), l.Verifier)
	switch {
	case errors.Is(err, errUnavailable):
		return req.deny(http.StatusBadGateway, err)
	case err != nil:
		return req.deny(http.StatusForbidden, err)
	}
	c := t.claims
	if err := m.checkLogin(c, l.Nonce, req.cert); err != nil {
		return req.deny(http.StatusForbidden, err, zap.String("sub", c.Subject))
	}

	now := m.now().Unix()
	cookie, err := m.sealSession(session{
		IDToken:      t.idToken,
		RefreshToken: t.refreshToken,
		RefreshedAt:  now,
		ExpiresAt:    now + int64(sessionLifetime.Seconds()),
		Host:         req.r.Host,
		Certificate:  req.cert,
	})
	if err != nil {
		req.log.Error("login failed", zap.String("sub", c.Subject), zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	http.SetCookie(req.w, cookie)
	req.log.Info("user logged in", zap.String("sub", c.Subject))

	if !isLocalPath(l.Redirect) {
		l.Redirect = "/"
	}
	http.Redirect(req.w, req.r, l.Redirect, http.StatusFound)
	return nil
}

func (m *Auth) checkLogin(c claims, nonce, cert string) error {
	switch {
	case c.Subject == "":
		return errors.New("ID token has no subject")
	case c.Nonce != nonce:
		return errors.New("ID token nonce does not match")
	case !m.DisableClientCertificate && certificateOwner(cert) != c.Subject:
		return errors.New("client certificate belongs to another user")
	case !slices.Contains(c.AMR, "phr"):
		return errors.New("login did not use a passkey")
	case m.now().Sub(time.Unix(c.AuthTime, 0)) > maxAuthAge:
		return errors.New("login is older than 1 hour")
	}
	return nil
}

func (m *Auth) logout(req *request) error {
	r := req.r.WithContext(req.r.Context())
	r.Method = req.orig.Method
	if err := crossOrigin.Check(r); err != nil {
		return req.deny(http.StatusForbidden, err)
	}
	expire(req.w, sessionCookie)
	s, sub, ok := m.openSession(req)
	if ok {
		if err := m.idp.endSession(context.WithoutCancel(req.r.Context()), s.IDToken); err != nil {
			req.log.Warn("logout did not end the login at the identity provider", zap.String("sub", sub), zap.Error(err))
		}
		req.log.Info("user logged out", zap.String("sub", sub))
	}
	http.Redirect(req.w, req.r, m.idp.logoutURL(s.IDToken, "https://"+req.r.Host+"/"), http.StatusSeeOther)
	return nil
}

func newAEAD(secret string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "castelnuovo_auth cookies", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (m *Auth) seal(name string, v any, maxAge int) (*http.Cookie, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	c := newCookie(name, base64.RawURLEncoding.EncodeToString(m.aead.Seal(nil, nil, plaintext, []byte(name))), maxAge)
	if len(c.String()) > maxCookieSize {
		return nil, errCookieTooLarge
	}
	return c, nil
}

func (m *Auth) open(name, value string, v any) error {
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	plaintext, err := m.aead.Open(nil, nil, ciphertext, []byte(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, v)
}

func expire(w http.ResponseWriter, name string) {
	http.SetCookie(w, newCookie(name, "", -1))
}

func newCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func takeCookies(r *http.Request) (session string, logins map[string]string) {
	logins = map[string]string{}
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookie:
				session = value
			case strings.HasPrefix(name, loginCookie):
				logins[strings.TrimPrefix(name, loginCookie)] = value
			case part != "":
				kept = append(kept, part)
			}
		}
	}
	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return session, logins
}

func removeAuthHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(r.Header, name)
		}
	}
}

func clientCertificate(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0][0].URIs) == 0 {
		return ""
	}
	return r.TLS.VerifiedChains[0][0].URIs[0].String()
}

func certificateOwner(uri string) string {
	if match := yubikeyURI.FindStringSubmatch(uri); match != nil {
		return match[1]
	}
	return ""
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, `\`) && !strings.ContainsFunc(p, unicode.IsControl)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}
