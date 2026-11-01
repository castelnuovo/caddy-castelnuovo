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
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	loginPath    = "/.castelnuovo/login"
	callbackPath = "/.castelnuovo/callback"
	logoutPath   = "/.castelnuovo/logout"

	sessionCookieName = "__Host-castelnuovo"
	loginCookieName   = "__Host-castelnuovo-login"
	maxCookieSize     = 4096

	sessionLifetime      = 12 * time.Hour
	refreshInterval      = 5 * time.Minute
	maxAuthenticationAge = time.Hour
	loginTimeout         = 10 * time.Minute
)

var (
	yubikeyCertificateURI = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	crossOriginProtection = http.NewCrossOriginProtection()
)

type requestState struct {
	response      http.ResponseWriter
	current       *http.Request
	original      *http.Request
	certificate   string
	sessionCookie string
	loginCookie   string
	log           *zap.Logger
}

func (auth *Auth) ServeHTTP(response http.ResponseWriter, httpRequest *http.Request, next caddyhttp.Handler) error {
	removeIncomingAuthHeaders(httpRequest)
	request := auth.newRequestState(response, httpRequest)
	if !auth.DisableClientCertificate && certificateOwner(request.certificate) == "" {
		return request.deny(http.StatusForbidden, errors.New("a client certificate of a user is required"))
	}

	switch path, method := request.original.URL.Path, request.original.Method; {
	case path == loginPath && method == http.MethodGet:
		auth.startLogin(request)
		return nil
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

func removeIncomingAuthHeaders(httpRequest *http.Request) {
	for name := range httpRequest.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(httpRequest.Header, name)
		}
	}
}

func (auth *Auth) newRequestState(response http.ResponseWriter, httpRequest *http.Request) *requestState {
	request := &requestState{response: response, current: httpRequest, original: httpRequest}
	if original, ok := httpRequest.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		request.original = &original
	}
	request.sessionCookie, request.loginCookie = extractOwnCookies(httpRequest)
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

func extractOwnCookies(httpRequest *http.Request) (sessionCookie, loginCookie string) {
	var kept []string
	for _, line := range httpRequest.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookieName:
				sessionCookie = value
			case name == loginCookieName:
				loginCookie = value
			case part != "":
				kept = append(kept, part)
			}
		}
	}
	httpRequest.Header.Del("Cookie")
	if len(kept) > 0 {
		httpRequest.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return sessionCookie, loginCookie
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

func (request *requestState) deny(status int, err error, fields ...zap.Field) error {
	request.log.Warn("request denied", append(fields, zap.String("path", request.original.URL.Path), zap.Error(err))...)
	return caddyhttp.Error(status, err)
}

func methodNotAllowed(response http.ResponseWriter, path, allow string) error {
	response.Header().Set("Allow", allow)
	return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts %s", path, allow))
}

type session struct {
	user         claims
	idToken      string
	refreshToken string
	host         string
	certificate  string
	refreshedAt  time.Time
	expiresAt    time.Time
}

func (auth *Auth) authenticate(request *requestState) (*claims, error) {
	now := auth.now()
	current, found := auth.sessions.get(request.sessionCookie)
	switch {
	case !found || !now.Before(current.expiresAt):
		return nil, nil
	case current.host != request.current.Host || current.certificate != request.certificate:
		request.log.Warn("session used from another host or certificate", zap.String("sub", current.user.Subject), zap.String("session_host", current.host), zap.String("session_certificate", current.certificate))
		return nil, nil
	case now.Sub(current.refreshedAt) < refreshInterval:
		return &current.user, nil
	}

	result, err, _ := auth.sessions.runningRefreshes.Do(request.sessionCookie, func() (any, error) {
		return auth.refreshSession(context.WithoutCancel(request.current.Context()), request.sessionCookie, current)
	})
	switch {
	case errors.Is(err, errUnavailable):
		return nil, request.deny(http.StatusBadGateway, err, zap.String("sub", current.user.Subject))
	case err != nil:
		auth.sessions.remove(request.sessionCookie)
		request.log.Warn("session ended", zap.String("sub", current.user.Subject), zap.Error(err))
		return nil, nil
	}
	refreshed := result.(session)
	return &refreshed.user, nil
}

func (auth *Auth) refreshSession(ctx context.Context, id string, current session) (session, error) {
	issued, err := auth.identityProvider.refreshTokens(ctx, current.refreshToken)
	switch {
	case err != nil:
		return session{}, err
	case issued.claims.Subject != current.user.Subject:
		return session{}, errors.New("refresh returned another user")
	}
	current.user, current.idToken, current.refreshToken, current.refreshedAt = issued.claims, issued.idToken, issued.refreshToken, auth.now()
	if !auth.sessions.replace(id, current) {
		return session{}, errors.New("session ended during the refresh")
	}
	return current, nil
}

func requireLogin(request *requestState) error {
	fetchMode, fetchDestination := request.current.Header.Get("Sec-Fetch-Mode"), request.current.Header.Get("Sec-Fetch-Dest")
	if request.original.Method != http.MethodGet || fetchMode != "" && fetchMode != "navigate" || fetchDestination != "" && fetchDestination != "document" {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(request.response, request.current, loginPath+"?rd="+url.QueryEscape(request.original.URL.RequestURI()), http.StatusFound)
	return nil
}

type pendingLogin struct {
	State        string `json:"s"`
	Nonce        string `json:"n"`
	CodeVerifier string `json:"v"`
	Redirect     string `json:"r,omitempty"`
}

func (auth *Auth) startLogin(request *requestState) {
	pending := pendingLogin{State: rand.Text(), Nonce: rand.Text(), CodeVerifier: oauth2.GenerateVerifier(), Redirect: request.original.URL.Query().Get("rd")}
	cookie := newCookie(loginCookieName, pending.encode(), int(loginTimeout.Seconds()))
	if len(cookie.String()) > maxCookieSize {
		pending.Redirect = ""
		cookie.Value = pending.encode()
	}
	http.SetCookie(request.response, cookie)
	http.Redirect(request.response, request.current, auth.identityProvider.authorizationURL(callbackURL(request.current.Host), pending.State, pending.Nonce, pending.CodeVerifier), http.StatusFound)
}

func (pending pendingLogin) encode() string {
	encoded, _ := json.Marshal(pending)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}

func (auth *Auth) finishLogin(request *requestState) error {
	query := request.original.URL.Query()
	pending, err := decodePendingLogin(request.loginCookie)
	switch {
	case request.loginCookie == "":
		return request.deny(http.StatusBadRequest, errors.New("callback without a pending login"))
	case err != nil || pending.State == "":
		expireCookie(request.response, loginCookieName)
		return request.deny(http.StatusBadRequest, errors.New("login cookie is invalid"))
	case pending.State != query.Get("state"):
		return request.deny(http.StatusBadRequest, errors.New("callback belongs to another login"))
	}
	expireCookie(request.response, loginCookieName)
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

	now := auth.now()
	auth.sessions.remove(request.sessionCookie)
	id := auth.sessions.add(session{
		user:         user,
		idToken:      issued.idToken,
		refreshToken: issued.refreshToken,
		host:         request.current.Host,
		certificate:  request.certificate,
		refreshedAt:  now,
		expiresAt:    now.Add(sessionLifetime),
	}, now)
	http.SetCookie(request.response, newCookie(sessionCookieName, id, int(sessionLifetime.Seconds())))
	request.log.Info("user logged in", zap.String("sub", user.Subject))

	if !isLocalPath(pending.Redirect) {
		pending.Redirect = "/"
	}
	http.Redirect(request.response, request.current, pending.Redirect, http.StatusFound)
	return nil
}

func decodePendingLogin(value string) (pendingLogin, error) {
	var pending pendingLogin
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		err = json.Unmarshal(decoded, &pending)
	}
	return pending, err
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

func isLocalPath(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.Contains(path, `\`) && !strings.ContainsFunc(path, unicode.IsControl)
}

func (auth *Auth) logout(request *requestState) error {
	withOriginalMethod := request.current.WithContext(request.current.Context())
	withOriginalMethod.Method = request.original.Method
	if err := crossOriginProtection.Check(withOriginalMethod); err != nil {
		return request.deny(http.StatusForbidden, err)
	}
	expireCookie(request.response, sessionCookieName)
	ended, found := auth.sessions.remove(request.sessionCookie)
	if found {
		request.log.Info("user logged out", zap.String("sub", ended.user.Subject))
	}
	http.Redirect(request.response, request.current, auth.identityProvider.logoutURL(ended.idToken, "https://"+request.current.Host+"/"), http.StatusSeeOther)
	return nil
}

type sessionStore struct {
	mutex            sync.Mutex
	sessions         map[string]session
	runningRefreshes singleflight.Group
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]session{}}
}

func (*sessionStore) Destruct() error {
	return nil
}

func (store *sessionStore) get(id string) (session, bool) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	found, ok := store.sessions[id]
	return found, ok
}

func (store *sessionStore) add(created session, now time.Time) string {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	for id, existing := range store.sessions {
		if !now.Before(existing.expiresAt) {
			delete(store.sessions, id)
		}
	}
	id := rand.Text()
	store.sessions[id] = created
	return id
}

func (store *sessionStore) replace(id string, refreshed session) bool {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if _, ok := store.sessions[id]; !ok {
		return false
	}
	store.sessions[id] = refreshed
	return true
}

func (store *sessionStore) remove(id string) (session, bool) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	removed, ok := store.sessions[id]
	delete(store.sessions, id)
	return removed, ok
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

func expireCookie(response http.ResponseWriter, name string) {
	http.SetCookie(response, newCookie(name, "", -1))
}
