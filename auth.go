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

	sessionCookieName = "__Host-castelnuovo"
	loginCookiePrefix = "__Host-castelnuovo-login-"
	maxCookieSize     = 4096

	sessionLifetime      = 12 * time.Hour
	refreshInterval      = 5 * time.Minute
	maxAuthenticationAge = time.Hour
	loginTimeout         = 10 * time.Minute
	maxPendingLogins     = 3
)

var (
	yubikeyCertificateURI = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	crossOriginProtection = http.NewCrossOriginProtection()
	errCookieTooLarge     = errors.New("cookie is larger than 4096 bytes")
)

type requestState struct {
	response      http.ResponseWriter
	current       *http.Request
	original      *http.Request
	certificate   string
	sessionCookie string
	loginCookies  map[string]string
	log           *zap.Logger
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
	Nonce        string `json:"n"`
	CodeVerifier string `json:"v"`
	Redirect     string `json:"r,omitempty"`
}

type refreshResult struct {
	cookie *http.Cookie
	claims claims
}

func (auth *Auth) ServeHTTP(response http.ResponseWriter, httpRequest *http.Request, next caddyhttp.Handler) error {
	removeIncomingAuthHeaders(httpRequest)
	request := auth.newRequestState(response, httpRequest)
	if !auth.DisableClientCertificate && certificateOwner(request.certificate) == "" {
		return request.deny(http.StatusForbidden, errors.New("a client certificate of a user is required"))
	}

	switch path, method := request.original.URL.Path, request.original.Method; {
	case path == loginPath && method == http.MethodGet:
		return auth.startLogin(request)
	case path == callbackPath && method == http.MethodGet:
		return auth.finishLogin(request)
	case path == logoutPath && method == http.MethodPost:
		return auth.logout(request)
	case path == loginPath || path == callbackPath:
		return methodNotAllowed(response, path, http.MethodGet)
	case path == logoutPath:
		return methodNotAllowed(response, path, http.MethodPost)
	}

	user, err := auth.authenticate(request)
	switch {
	case err != nil:
		return err
	case user == nil:
		return requireLogin(request)
	}
	httpRequest.Header.Set("X-Auth-Sub", user.Subject)
	httpRequest.Header.Set("X-Auth-User", user.PreferredUsername)
	httpRequest.Header.Set("X-Auth-Name", user.Name)
	httpRequest.Header.Set("X-Auth-Email", user.Email)
	httpRequest.Header.Set("X-Auth-Groups", strings.Join(user.Groups, ","))
	return next.ServeHTTP(response, httpRequest)
}

func (auth *Auth) newRequestState(response http.ResponseWriter, httpRequest *http.Request) *requestState {
	request := &requestState{response: response, current: httpRequest, original: httpRequest}
	if original, ok := httpRequest.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		request.original = &original
	}
	request.sessionCookie, request.loginCookies = extractOwnCookies(httpRequest)
	if !auth.DisableClientCertificate {
		request.certificate = clientCertificateURI(httpRequest)
	}

	fields := []zap.Field{zap.String("host", httpRequest.Host)}
	if request.certificate != "" {
		fields = append(fields, zap.String("certificate", request.certificate))
	}
	if clientIP, _ := caddyhttp.GetVar(httpRequest.Context(), caddyhttp.ClientIPVarKey).(string); clientIP != "" {
		fields = append(fields, zap.String("client_ip", clientIP))
	}
	request.log = auth.log.WithLazy(fields...)
	return request
}

func (request *requestState) deny(status int, err error, fields ...zap.Field) error {
	request.log.Warn("request denied", append(fields, zap.String("path", request.original.URL.Path), zap.Error(err))...)
	return caddyhttp.Error(status, err)
}

func requireLogin(request *requestState) error {
	fetchMode, fetchDestination := request.current.Header.Get("Sec-Fetch-Mode"), request.current.Header.Get("Sec-Fetch-Dest")
	if request.original.Method != http.MethodGet || fetchMode != "" && fetchMode != "navigate" || fetchDestination != "" && fetchDestination != "document" {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(request.response, request.current, loginPath+"?rd="+url.QueryEscape(request.original.URL.RequestURI()), http.StatusFound)
	return nil
}

func methodNotAllowed(response http.ResponseWriter, path, allow string) error {
	response.Header().Set("Allow", allow)
	return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts %s", path, allow))
}

func (auth *Auth) authenticate(request *requestState) (*claims, error) {
	now := auth.now().Unix()
	stored, subject, ok := auth.openSessionCookie(request)
	switch {
	case !ok || now >= stored.ExpiresAt:
		return nil, nil
	case stored.Host != request.current.Host || stored.Certificate != request.certificate:
		request.log.Warn("session used from another host or certificate", zap.String("sub", subject), zap.String("session_host", stored.Host), zap.String("session_certificate", stored.Certificate))
		return nil, nil
	}
	ctx := context.WithoutCancel(request.current.Context())
	if now-stored.RefreshedAt < int64(refreshInterval.Seconds()) {
		if verifiedUser, err := auth.identityProvider.verifyIDToken(ctx, stored.IDToken); err == nil {
			return &verifiedUser, nil
		}
	}

	result, err, _ := auth.runningRefreshes.Do(stored.RefreshToken, func() (any, error) {
		return auth.refreshSession(ctx, stored, subject)
	})
	switch {
	case errors.Is(err, errUnavailable):
		return nil, request.deny(http.StatusBadGateway, err, zap.String("sub", subject))
	case err != nil:
		expireCookie(request.response, sessionCookieName)
		request.log.Warn("session ended", zap.String("sub", subject), zap.Error(err))
		return nil, nil
	}
	refreshed := result.(refreshResult)
	http.SetCookie(request.response, refreshed.cookie)
	return &refreshed.claims, nil
}

func (auth *Auth) refreshSession(ctx context.Context, stored session, subject string) (refreshResult, error) {
	issued, err := auth.identityProvider.refreshTokens(ctx, stored.RefreshToken)
	switch {
	case err != nil:
		return refreshResult{}, err
	case issued.claims.Subject != subject:
		return refreshResult{}, errors.New("refresh returned another user")
	}
	now := auth.now().Unix()
	if now >= stored.ExpiresAt {
		return refreshResult{}, errors.New("session expired during the refresh")
	}
	stored.IDToken, stored.RefreshToken, stored.RefreshedAt = issued.idToken, issued.refreshToken, now
	cookie, err := auth.sealSessionCookie(stored)
	return refreshResult{cookie, issued.claims}, err
}

func (auth *Auth) openSessionCookie(request *requestState) (stored session, subject string, ok bool) {
	if auth.openCookie(sessionCookieName, request.sessionCookie, &stored) != nil {
		return session{}, "", false
	}
	unverified, err := parseUnverifiedClaims(stored.IDToken)
	return stored, unverified.Subject, err == nil
}

func (auth *Auth) sealSessionCookie(stored session) (*http.Cookie, error) {
	return auth.sealCookie(sessionCookieName, stored, int(stored.ExpiresAt-stored.RefreshedAt))
}

func (auth *Auth) startLogin(request *requestState) error {
	if len(request.loginCookies) >= maxPendingLogins {
		for pendingState := range request.loginCookies {
			expireCookie(request.response, loginCookiePrefix+pendingState)
		}
	}
	state := rand.Text()
	pending := pendingLogin{Nonce: rand.Text(), CodeVerifier: oauth2.GenerateVerifier(), Redirect: request.original.URL.Query().Get("rd")}
	cookie, err := auth.sealCookie(loginCookiePrefix+state, pending, int(loginTimeout.Seconds()))
	if errors.Is(err, errCookieTooLarge) {
		pending.Redirect = ""
		cookie, err = auth.sealCookie(loginCookiePrefix+state, pending, int(loginTimeout.Seconds()))
	}
	if err != nil {
		return err
	}
	http.SetCookie(request.response, cookie)
	http.Redirect(request.response, request.current, auth.identityProvider.authorizationURL(callbackURL(request.current.Host), state, pending.Nonce, pending.CodeVerifier), http.StatusFound)
	return nil
}

func (auth *Auth) finishLogin(request *requestState) error {
	query := request.original.URL.Query()
	state := query.Get("state")
	sealedLogin, ok := request.loginCookies[state]
	if !ok {
		return request.deny(http.StatusBadRequest, errors.New("callback without a pending login"))
	}
	expireCookie(request.response, loginCookiePrefix+state)
	var pending pendingLogin
	if err := auth.openCookie(loginCookiePrefix+state, sealedLogin, &pending); err != nil {
		return request.deny(http.StatusBadRequest, errors.New("login cookie is invalid"))
	}
	if query.Get("code") == "" {
		return request.deny(http.StatusForbidden, errors.New("identity provider returned an error"), zap.String("idp_error", query.Get("error")))
	}

	issued, err := auth.identityProvider.exchangeCode(request.current.Context(), callbackURL(request.current.Host), query.Get("code"), pending.CodeVerifier)
	switch {
	case errors.Is(err, errUnavailable):
		return request.deny(http.StatusBadGateway, err)
	case err != nil:
		return request.deny(http.StatusForbidden, err)
	}
	user := issued.claims
	if err := auth.checkLoginClaims(user, pending.Nonce, request.certificate); err != nil {
		return request.deny(http.StatusForbidden, err, zap.String("sub", user.Subject))
	}

	now := auth.now().Unix()
	cookie, err := auth.sealSessionCookie(session{
		IDToken:      issued.idToken,
		RefreshToken: issued.refreshToken,
		RefreshedAt:  now,
		ExpiresAt:    now + int64(sessionLifetime.Seconds()),
		Host:         request.current.Host,
		Certificate:  request.certificate,
	})
	if err != nil {
		request.log.Error("login failed", zap.String("sub", user.Subject), zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	http.SetCookie(request.response, cookie)
	request.log.Info("user logged in", zap.String("sub", user.Subject))

	if !isLocalPath(pending.Redirect) {
		pending.Redirect = "/"
	}
	http.Redirect(request.response, request.current, pending.Redirect, http.StatusFound)
	return nil
}

func (auth *Auth) checkLoginClaims(user claims, nonce, certificate string) error {
	switch {
	case user.Subject == "":
		return errors.New("ID token has no subject")
	case user.Nonce != nonce:
		return errors.New("ID token nonce does not match")
	case !auth.DisableClientCertificate && certificateOwner(certificate) != user.Subject:
		return errors.New("client certificate belongs to another user")
	case !slices.Contains(user.AuthenticationMethods, "phr"):
		return errors.New("login did not use a passkey")
	case auth.now().Sub(time.Unix(user.AuthenticatedAt, 0)) > maxAuthenticationAge:
		return errors.New("login is older than 1 hour")
	}
	return nil
}

func (auth *Auth) logout(request *requestState) error {
	withOriginalMethod := request.current.WithContext(request.current.Context())
	withOriginalMethod.Method = request.original.Method
	if err := crossOriginProtection.Check(withOriginalMethod); err != nil {
		return request.deny(http.StatusForbidden, err)
	}
	expireCookie(request.response, sessionCookieName)
	stored, subject, ok := auth.openSessionCookie(request)
	if ok {
		if err := auth.identityProvider.endSession(context.WithoutCancel(request.current.Context()), stored.IDToken); err != nil {
			request.log.Warn("logout did not end the login at the identity provider", zap.String("sub", subject), zap.Error(err))
		}
		request.log.Info("user logged out", zap.String("sub", subject))
	}
	http.Redirect(request.response, request.current, auth.identityProvider.logoutURL(stored.IDToken, "https://"+request.current.Host+"/"), http.StatusSeeOther)
	return nil
}

func newCookieCipher(secret string) (cipher.AEAD, error) {
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

func (auth *Auth) sealCookie(name string, value any, maxAge int) (*http.Cookie, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	cookie := newCookie(name, base64.RawURLEncoding.EncodeToString(auth.cookieCipher.Seal(nil, nil, plaintext, []byte(name))), maxAge)
	if len(cookie.String()) > maxCookieSize {
		return nil, errCookieTooLarge
	}
	return cookie, nil
}

func (auth *Auth) openCookie(name, sealedValue string, target any) error {
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealedValue)
	if err != nil {
		return err
	}
	plaintext, err := auth.cookieCipher.Open(nil, nil, ciphertext, []byte(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, target)
}

func expireCookie(response http.ResponseWriter, name string) {
	http.SetCookie(response, newCookie(name, "", -1))
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

func extractOwnCookies(httpRequest *http.Request) (sessionCookie string, loginCookies map[string]string) {
	loginCookies = map[string]string{}
	var kept []string
	for _, line := range httpRequest.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookieName:
				sessionCookie = value
			case strings.HasPrefix(name, loginCookiePrefix):
				loginCookies[strings.TrimPrefix(name, loginCookiePrefix)] = value
			case part != "":
				kept = append(kept, part)
			}
		}
	}
	httpRequest.Header.Del("Cookie")
	if len(kept) > 0 {
		httpRequest.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return sessionCookie, loginCookies
}

func removeIncomingAuthHeaders(httpRequest *http.Request) {
	for name := range httpRequest.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(httpRequest.Header, name)
		}
	}
}

func clientCertificateURI(httpRequest *http.Request) string {
	if httpRequest.TLS == nil || len(httpRequest.TLS.VerifiedChains) == 0 || len(httpRequest.TLS.VerifiedChains[0][0].URIs) == 0 {
		return ""
	}
	return httpRequest.TLS.VerifiedChains[0][0].URIs[0].String()
}

func certificateOwner(uri string) string {
	if match := yubikeyCertificateURI.FindStringSubmatch(uri); match != nil {
		return match[1]
	}
	return ""
}

func isLocalPath(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.Contains(path, `\`) && !strings.ContainsFunc(path, unicode.IsControl)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}
