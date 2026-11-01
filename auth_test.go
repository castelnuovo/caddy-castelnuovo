package castelnuovo

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
)

const (
	userID                  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	otherUserID             = "11111111-2222-3333-4444-555555555555"
	userCertificate         = "spiffe://castelnuovo.eu/yubikey/87654321/owner/" + userID
	otherYubikeyCertificate = "spiffe://castelnuovo.eu/yubikey/12345678/owner/" + userID
	otherUserCertificate    = "spiffe://castelnuovo.eu/yubikey/12345678/owner/" + otherUserID
	host                    = "app.castelnuovo.eu"
	clientID                = "5f0c2b8e-3d4a-4e6f-9a1b-7c8d9e0f1a2b"
	clientIP                = "203.0.113.7"
)

var errInvalidGrant = errors.New("invalid_grant")

type grant struct {
	authenticatedAt int64
	revoked         bool
}

type authorization struct {
	nonce, codeChallenge, redirectURL string
	authenticatedAt                   int64
}

type issuedToken struct {
	grant *grant
	used  bool
}

type fakePocketID struct {
	*oidcClient
	clock     atomic.Int64
	onRefresh func()

	mutex               sync.Mutex
	user                claims
	down                bool
	disabled            bool
	refreshes           int
	lastIDToken         string
	codes               map[string]authorization
	issuedRefreshTokens map[string]*issuedToken
}

func (fake *fakePocketID) now() time.Time {
	return time.Unix(0, fake.clock.Load())
}

func (fake *fakePocketID) advance(duration time.Duration) {
	fake.clock.Add(int64(duration))
}

func (fake *fakePocketID) approveLogin(location string) string {
	query := must(url.Parse(location)).Query()
	code := rand.Text()
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.codes[code] = authorization{query.Get("nonce"), query.Get("code_challenge"), query.Get("redirect_uri"), fake.now().Unix()}
	return query.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {query.Get("state")}}.Encode()
}

func (fake *fakePocketID) exchangeCode(_ context.Context, redirectURL, code, verifier string) (tokenResponse, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	pendingAuthorization, ok := fake.codes[code]
	delete(fake.codes, code)
	switch {
	case fake.down:
		return tokenResponse{}, errUnavailable
	case !ok || pendingAuthorization.redirectURL != redirectURL || pendingAuthorization.codeChallenge != oauth2.S256ChallengeFromVerifier(verifier):
		return tokenResponse{}, errInvalidGrant
	}
	return fake.issueTokens(&grant{authenticatedAt: pendingAuthorization.authenticatedAt}, pendingAuthorization.nonce), nil
}

func (fake *fakePocketID) issueTokens(issuedGrant *grant, nonce string) tokenResponse {
	user := fake.user
	if user.Nonce == "" {
		user.Nonce = nonce
	}
	if user.AuthenticatedAt == 0 {
		user.AuthenticatedAt = issuedGrant.authenticatedAt
	}
	issued := tokenResponse{idToken: "id-token-" + rand.Text(), refreshToken: "refresh-token-" + rand.Text(), claims: user}
	fake.issuedRefreshTokens[issued.refreshToken] = &issuedToken{grant: issuedGrant}
	fake.lastIDToken = issued.idToken
	return issued
}

func (fake *fakePocketID) refreshTokens(ctx context.Context, refreshToken string) (tokenResponse, error) {
	if fake.onRefresh != nil {
		fake.onRefresh()
	}
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.refreshes++
	issued, ok := fake.issuedRefreshTokens[refreshToken]
	switch {
	case ctx.Err() != nil:
		return tokenResponse{}, fmt.Errorf("%w: %w", errUnavailable, ctx.Err())
	case fake.down:
		return tokenResponse{}, errUnavailable
	case !ok || issued.grant.revoked || fake.disabled:
		return tokenResponse{}, errInvalidGrant
	case issued.used:
		issued.grant.revoked = true
		return tokenResponse{}, errInvalidGrant
	}
	issued.used = true
	return fake.issueTokens(issued.grant, ""), nil
}

func newTestAuth(t *testing.T) (*Auth, *fakePocketID) {
	provider := &fakePocketID{
		oidcClient: newOIDCClient(issuer, clientID, "secret", nil),
		user: claims{
			Subject:               userID,
			PreferredUsername:     "luca",
			Name:                  "Luca Castelnuovo",
			Email:                 "luca@castelnuovo.eu",
			Groups:                []string{"admins", "users"},
			AuthenticationMethods: []string{"phr"},
		},
		codes:               map[string]authorization{},
		issuedRefreshTokens: map[string]*issuedToken{},
	}
	provider.clock.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	return &Auth{sessions: newSessionStore(), identityProvider: provider, now: provider.now, log: zap.NewNop()}, provider
}

func newHTTPRequest(method, target, uri string, cookies ...*http.Cookie) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Host = host
	if uri != "" {
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{must(url.Parse(uri))}}}}}
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request = caddyhttp.PrepareRequest(request, caddy.NewReplacer(), nil, nil)
	caddyhttp.SetVar(request.Context(), caddyhttp.ClientIPVarKey, clientIP)
	return request
}

func serve(t *testing.T, auth *Auth, request *http.Request) *http.Response {
	t.Helper()
	recorder := httptest.NewRecorder()
	app := caddyhttp.HandlerFunc(func(writer http.ResponseWriter, forwarded *http.Request) error {
		maps.Copy(writer.Header(), forwarded.Header)
		return nil
	})
	if err := auth.ServeHTTP(recorder, request, app); err != nil {
		if handlerError, ok := errors.AsType[caddyhttp.HandlerError](err); ok {
			recorder.WriteHeader(handlerError.StatusCode)
		} else {
			t.Errorf("handler returned %v", err)
		}
	}
	response := recorder.Result()
	for _, line := range response.Header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		if err != nil || len(line) > maxCookieSize || cookie.MaxAge == 0 || !strings.HasPrefix(cookie.Name, "__Host-") || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("unsafe cookie %q", line)
		}
	}
	return response
}

func get(t *testing.T, auth *Auth, target, uri string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	return serve(t, auth, newHTTPRequest(http.MethodGet, target, uri, cookies...))
}

func cookieNamed(response *http.Response, name string) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func pendingLoginCookie(response *http.Response) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if strings.HasPrefix(cookie.Name, loginCookiePrefix) && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}

func logIn(t *testing.T, auth *Auth, provider *fakePocketID, uri string) *http.Cookie {
	t.Helper()
	response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath+"?rd=%2Fpage", uri), uri)
	session := cookieNamed(response, sessionCookieName)
	if response.StatusCode != http.StatusFound || session == nil || session.MaxAge <= 0 {
		t.Fatalf("login: %d %v", response.StatusCode, response.Cookies())
	}
	return session
}

func completeLoginAtProvider(t *testing.T, auth *Auth, provider *fakePocketID, login *http.Response, uri string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	return get(t, auth, provider.approveLogin(login.Header.Get("Location")), uri, append(cookies, pendingLoginCookie(login))...)
}

func tamper(value string) string {
	characters := []byte(value)
	if characters[len(characters)/2] == 'A' {
		characters[len(characters)/2] = 'B'
	} else {
		characters[len(characters)/2] = 'A'
	}
	return string(characters)
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func TestProtectedRequest(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)

	request := newHTTPRequest(http.MethodGet, "/page", userCertificate, session, &http.Cookie{Name: "app", Value: "kept"}, &http.Cookie{Name: loginCookiePrefix + "STATE", Value: "x"}, &http.Cookie{Name: "__Host-castelnuovo-app", Value: "kept"})
	request.Header.Set("X-Auth-User", "spoofed")
	request.Header.Set("X-Auth-Admin", "spoofed")
	request.Header["X_Auth_Groups"] = []string{"spoofed"}
	request.Header["x_auth_role"] = []string{"spoofed"}
	response := serve(t, auth, request)
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("status %d, cookies %v", response.StatusCode, response.Cookies())
	}

	want := map[string]string{
		"X-Auth-Sub":    userID,
		"X-Auth-User":   "luca",
		"X-Auth-Name":   "Luca Castelnuovo",
		"X-Auth-Email":  "luca@castelnuovo.eu",
		"X-Auth-Groups": "admins,users",
		"Cookie":        "app=kept; __Host-castelnuovo-app=kept",
	}
	for name, value := range want {
		if got := response.Header.Values(name); !slices.Equal(got, []string{value}) {
			t.Errorf("%s: %q, want %q", name, got, value)
		}
	}
	for name := range response.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") && want[name] == "" {
			t.Errorf("app received %s", name)
		}
	}
}

func TestExtractOwnCookies(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Add("Cookie", "a=1; __Host-castelnuovo=old; "+loginCookiePrefix+"ONE=x")
	request.Header.Add("Cookie", " b = 2 ;__Host-castelnuovo=new;; __Host-castelnuovo-app=3; "+loginCookiePrefix+"TWO=y")
	session, logins := extractOwnCookies(request)
	if session != "new" || len(logins) != 2 || logins["ONE"] != "x" || logins["TWO"] != "y" {
		t.Fatalf("%q %v", session, logins)
	}
	if got := request.Header.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b = 2; __Host-castelnuovo-app=3" {
		t.Fatalf("kept %q", got)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Cookie", sessionCookieName+"=only")
	if session, _ := extractOwnCookies(request); session != "only" || request.Header.Values("Cookie") != nil {
		t.Fatalf("%q kept %q", session, request.Header.Values("Cookie"))
	}
}

func TestClientCertificateRequired(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)
	for name, uri := range map[string]string{
		"no certificate":            "",
		"machine certificate":       "spiffe://castelnuovo.eu/client/backup",
		"certificate without owner": "spiffe://castelnuovo.eu/yubikey/87654321",
		"owner is not a user ID":    "spiffe://castelnuovo.eu/yubikey/87654321/owner/luca",
		"another trust domain":      "spiffe://example.com/yubikey/87654321/owner/" + userID,
		"owner followed by a path":  userCertificate + "/x",
		"user URI inside another":   "spiffe://example.com/" + userCertificate,
	} {
		for path, method := range map[string]string{"/page": http.MethodGet, loginPath: http.MethodGet, callbackPath: http.MethodGet, logoutPath: http.MethodPost} {
			if response := serve(t, auth, newHTTPRequest(method, path, uri, session)); response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 {
				t.Fatalf("%s on %s: %d %v", name, path, response.StatusCode, response.Cookies())
			}
		}
	}

	unverified := newHTTPRequest(http.MethodGet, "/page", userCertificate, session)
	unverified.TLS = &tls.ConnectionState{PeerCertificates: unverified.TLS.VerifiedChains[0]}
	second := newHTTPRequest(http.MethodGet, "/page", "spiffe://castelnuovo.eu/client/backup", session)
	second.TLS.VerifiedChains[0][0].URIs = append(second.TLS.VerifiedChains[0][0].URIs, must(url.Parse(userCertificate)))
	for name, request := range map[string]*http.Request{"unverified certificate": unverified, "user URI after another URI": second} {
		if response := serve(t, auth, request); response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %d", name, response.StatusCode)
		}
	}
}

func TestWithoutCertificate(t *testing.T) {
	auth, provider := newTestAuth(t)
	auth.DisableClientCertificate = true
	session := logIn(t, auth, provider, "")
	if response := get(t, auth, "/page", otherUserCertificate, session); response.StatusCode != http.StatusOK || response.Header.Get("X-Auth-Sub") != userID {
		t.Fatalf("certificate is ignored: %d", response.StatusCode)
	}

	auth.DisableClientCertificate = false
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusFound {
		t.Fatalf("site that requires a certificate: %d", response.StatusCode)
	}
}

func TestRoutesOnOriginalRequest(t *testing.T) {
	auth, provider := newTestAuth(t)
	rewritten := func(method, original, target string) *http.Request {
		request := newHTTPRequest(method, original, userCertificate)
		request.Method, request.URL, request.RequestURI = http.MethodGet, must(url.Parse(target)), target
		return request
	}

	if response := serve(t, auth, rewritten(http.MethodGet, "/app/page?x=1", "/page?x=1")); response.StatusCode != http.StatusFound || response.Header.Get("Location") != loginPath+"?rd=%2Fapp%2Fpage%3Fx%3D1" {
		t.Fatalf("stripped prefix: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	if response := serve(t, auth, rewritten(http.MethodGet, "/secret", loginPath)); response.StatusCode != http.StatusFound || response.Header.Get("Location") != loginPath+"?rd=%2Fsecret" || pendingLoginCookie(response) != nil {
		t.Fatalf("rewritten to the login: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	response := completeLoginAtProvider(t, auth, provider, serve(t, auth, rewritten(http.MethodGet, loginPath+"?rd=%2Fapp%2Fpage", "/page")), userCertificate)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/app/page" {
		t.Fatalf("login rewritten to the app: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	if response := serve(t, auth, rewritten(http.MethodPost, logoutPath, "/page")); response.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout with a rewritten method: %d", response.StatusCode)
	}
	crossSite := rewritten(http.MethodPost, logoutPath, "/page")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	if response := serve(t, auth, crossSite); response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross site logout with a rewritten method: %d", response.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	auth, _ := newTestAuth(t)
	for path, allow := range map[string]string{loginPath: http.MethodGet, callbackPath: http.MethodGet, logoutPath: http.MethodPost} {
		method := http.MethodPost
		if allow == http.MethodPost {
			method = http.MethodGet
		}
		if response := serve(t, auth, newHTTPRequest(method, path, userCertificate)); response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != allow {
			t.Fatalf("%s %s: %d, Allow %q", method, path, response.StatusCode, response.Header.Get("Allow"))
		}
	}
}

func TestSessionBinding(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)
	for name, test := range map[string]struct{ host, uri string }{
		"another YubiKey of the same user": {host, otherYubikeyCertificate},
		"certificate of another user":      {host, otherUserCertificate},
		"another host":                     {"other.castelnuovo.eu", userCertificate},
	} {
		request := newHTTPRequest(http.MethodGet, "/page", test.uri, session)
		request.Host = test.host
		if response := serve(t, auth, request); response.StatusCode != http.StatusFound || response.Header.Get("X-Auth-Sub") != "" {
			t.Fatalf("%s: %d", name, response.StatusCode)
		}
	}
	if response := get(t, auth, "/page", userCertificate, &http.Cookie{Name: sessionCookieName, Value: "unknown"}); response.StatusCode != http.StatusFound {
		t.Fatalf("unknown session: %d", response.StatusCode)
	}
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK {
		t.Fatalf("own host and certificate: %d", response.StatusCode)
	}
}

func TestRefresh(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)

	provider.advance(refreshInterval - time.Second)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK || provider.refreshes != 0 {
		t.Fatalf("before the refresh is due: %d, %d refreshes", response.StatusCode, provider.refreshes)
	}

	provider.user.Groups = []string{"admins"}
	provider.advance(time.Second)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK || len(response.Cookies()) != 0 || provider.refreshes != 1 || response.Header.Get("X-Auth-Groups") != "admins" {
		t.Fatalf("refresh: %d %v, %d refreshes, groups %q", response.StatusCode, response.Cookies(), provider.refreshes, response.Header.Get("X-Auth-Groups"))
	}
	provider.advance(refreshInterval)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK || provider.refreshes != 2 {
		t.Fatalf("refresh with the rotated token: %d, %d refreshes", response.StatusCode, provider.refreshes)
	}
}

func TestRefreshEndsSession(t *testing.T) {
	tests := map[string]func(*fakePocketID){
		"user disabled": func(fake *fakePocketID) { fake.disabled = true },
		"another user":  func(fake *fakePocketID) { fake.user.Subject = otherUserID },
		"login revoked at the provider": func(fake *fakePocketID) {
			for _, issued := range fake.issuedRefreshTokens {
				issued.grant.revoked = true
			}
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			auth, provider := newTestAuth(t)
			core, logs := observer.New(zap.InfoLevel)
			auth.log = zap.New(core)
			session := logIn(t, auth, provider, userCertificate)
			change(provider)
			provider.advance(refreshInterval)

			if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusFound || response.Header.Get("Location") != loginPath+"?rd=%2Fpage" {
				t.Fatalf("%d %s", response.StatusCode, response.Header.Get("Location"))
			}
			if _, found := auth.sessions.get(session.Value); found {
				t.Fatal("session kept")
			}
			if entries := logs.FilterMessage("session ended").All(); len(entries) != 1 || entries[0].ContextMap()["sub"] != userID {
				t.Fatalf("logs: %v", logs.All())
			}
		})
	}
}

func TestUnavailableIdentityProvider(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)
	provider.down = true

	provider.advance(refreshInterval - time.Second)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK {
		t.Fatalf("before the refresh is due: %d", response.StatusCode)
	}
	provider.advance(time.Second)
	for attempt := range 2 {
		if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusBadGateway || len(response.Cookies()) != 0 || response.Header.Get("X-Auth-Sub") != "" || provider.refreshes != attempt+1 {
			t.Fatalf("refresh due: %d %v, %d refreshes", response.StatusCode, response.Cookies(), provider.refreshes)
		}
	}

	provider.down = false
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK || provider.refreshes != 3 {
		t.Fatalf("after the outage: %d", response.StatusCode)
	}
}

func TestConcurrentRefreshes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		auth, provider := newTestAuth(t)
		session := logIn(t, auth, provider, userCertificate)
		provider.advance(refreshInterval)
		release := make(chan struct{})
		provider.onRefresh = func() { <-release }

		responses := make([]*http.Response, 5)
		var waitGroup sync.WaitGroup
		for index := range responses {
			waitGroup.Go(func() { responses[index] = get(t, auth, "/page", userCertificate, session) })
		}
		synctest.Wait()
		close(release)
		waitGroup.Wait()

		for _, response := range responses {
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Auth-Sub") != userID {
				t.Fatalf("%d", response.StatusCode)
			}
		}
		if provider.refreshes != 1 {
			t.Fatalf("%d refreshes", provider.refreshes)
		}
	})
}

func TestCancelledRequestKeepsRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		auth, provider := newTestAuth(t)
		session := logIn(t, auth, provider, userCertificate)
		provider.advance(refreshInterval)
		release := make(chan struct{})
		provider.onRefresh = func() { <-release }

		first := newHTTPRequest(http.MethodGet, "/page", userCertificate, session)
		ctx, cancel := context.WithCancel(first.Context())
		var waitGroup sync.WaitGroup
		var waiting *http.Response
		waitGroup.Go(func() { serve(t, auth, first.WithContext(ctx)) })
		synctest.Wait()
		waitGroup.Go(func() { waiting = get(t, auth, "/page", userCertificate, session) })
		synctest.Wait()
		cancel()
		close(release)
		waitGroup.Wait()

		if waiting.StatusCode != http.StatusOK || provider.refreshes != 1 {
			t.Fatalf("%d, %d refreshes", waiting.StatusCode, provider.refreshes)
		}
	})
}

func TestLogoutDuringRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		auth, provider := newTestAuth(t)
		session := logIn(t, auth, provider, userCertificate)
		provider.advance(refreshInterval)
		release := make(chan struct{})
		provider.onRefresh = func() { <-release }

		var waitGroup sync.WaitGroup
		var refreshing *http.Response
		waitGroup.Go(func() { refreshing = get(t, auth, "/page", userCertificate, session) })
		synctest.Wait()
		if response := serve(t, auth, newHTTPRequest(http.MethodPost, logoutPath, userCertificate, session)); response.StatusCode != http.StatusSeeOther {
			t.Fatalf("logout: %d", response.StatusCode)
		}
		close(release)
		waitGroup.Wait()

		if refreshing.StatusCode != http.StatusFound {
			t.Fatalf("request whose refresh finished after the logout: %d", refreshing.StatusCode)
		}
		if _, found := auth.sessions.get(session.Value); found {
			t.Fatal("the refresh brought the session back")
		}
	})
}

func TestSessionExpires(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)

	provider.advance(sessionLifetime - time.Second)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusOK {
		t.Fatalf("last second: %d", response.StatusCode)
	}
	provider.advance(time.Second)
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusFound || provider.refreshes != 1 {
		t.Fatalf("after 12 hours: %d, %d refreshes", response.StatusCode, provider.refreshes)
	}
}

func TestRequireLogin(t *testing.T) {
	auth, _ := newTestAuth(t)
	tests := map[string]struct {
		method, fetchMode, fetchDestination string
		status                              int
	}{
		"page load":                 {http.MethodGet, "navigate", "document", http.StatusFound},
		"without fetch metadata":    {http.MethodGet, "", "", http.StatusFound},
		"frame":                     {http.MethodGet, "navigate", "iframe", http.StatusUnauthorized},
		"fetch":                     {http.MethodGet, "cors", "empty", http.StatusUnauthorized},
		"websocket":                 {http.MethodGet, "websocket", "websocket", http.StatusUnauthorized},
		"form post":                 {http.MethodPost, "navigate", "document", http.StatusUnauthorized},
		"head":                      {http.MethodHead, "", "", http.StatusUnauthorized},
		"fetch without destination": {http.MethodGet, "no-cors", "", http.StatusUnauthorized},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := newHTTPRequest(test.method, "/page?x=1", userCertificate)
			request.Header.Set("Sec-Fetch-Mode", test.fetchMode)
			request.Header.Set("Sec-Fetch-Dest", test.fetchDestination)
			response := serve(t, auth, request)
			if response.StatusCode != test.status || len(response.Cookies()) != 0 {
				t.Fatalf("status %d, want %d, cookies %v", response.StatusCode, test.status, response.Cookies())
			}
			if test.status == http.StatusFound && response.Header.Get("Location") != loginPath+"?rd=%2Fpage%3Fx%3D1" {
				t.Fatalf("redirected to %s", response.Header.Get("Location"))
			}
		})
	}
}

func TestLogin(t *testing.T) {
	auth, provider := newTestAuth(t)
	response := get(t, auth, loginPath+"?rd=%2Fpage", userCertificate)
	login := pendingLoginCookie(response)
	location := must(url.Parse(response.Header.Get("Location")))
	query := location.Query()
	if response.StatusCode != http.StatusFound || location.Scheme+"://"+location.Host+location.Path != issuer+"/authorize" || login == nil || login.Name != loginCookiePrefix+query.Get("state") || login.MaxAge != int(loginTimeout.Seconds()) {
		t.Fatalf("login: %d %s %v", response.StatusCode, location, response.Cookies())
	}
	if query.Get("redirect_uri") != "https://"+host+callbackPath || query.Get("code_challenge_method") != "S256" || query.Get("max_age") != "3600" || query.Get("nonce") == "" || query.Has("prompt") {
		t.Fatalf("authorize URL %s", location)
	}

	response = completeLoginAtProvider(t, auth, provider, response, userCertificate)
	session, expired := cookieNamed(response, sessionCookieName), cookieNamed(response, login.Name)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/page" || session == nil || session.MaxAge != int(sessionLifetime.Seconds()) || expired == nil || expired.MaxAge >= 0 {
		t.Fatalf("callback: %d %s %v", response.StatusCode, response.Header.Get("Location"), response.Cookies())
	}
}

func TestLoginReplacesSession(t *testing.T) {
	auth, provider := newTestAuth(t)
	first := logIn(t, auth, provider, userCertificate)
	second := cookieNamed(completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath, userCertificate, first), userCertificate, first), sessionCookieName)
	if second == nil || second.Value == first.Value {
		t.Fatalf("second login set %v", second)
	}
	if response := get(t, auth, "/page", userCertificate, first); response.StatusCode != http.StatusFound {
		t.Fatalf("replaced session: %d", response.StatusCode)
	}
	if response := get(t, auth, "/page", userCertificate, second); response.StatusCode != http.StatusOK {
		t.Fatalf("new session: %d", response.StatusCode)
	}
}

func TestConcurrentLogins(t *testing.T) {
	auth, provider := newTestAuth(t)
	first, second := get(t, auth, loginPath+"?rd=%2Ffirst", userCertificate), get(t, auth, loginPath+"?rd=%2Fsecond", userCertificate)
	logins := map[*http.Response]*http.Cookie{first: pendingLoginCookie(first), second: pendingLoginCookie(second)}
	for login, want := range map[*http.Response]string{second: "/second", first: "/first"} {
		response := get(t, auth, provider.approveLogin(login.Header.Get("Location")), userCertificate, logins[first], logins[second])
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != want || cookieNamed(response, sessionCookieName) == nil {
			t.Fatalf("%s: %d %s", want, response.StatusCode, response.Header.Get("Location"))
		}
		if expired := cookieNamed(response, logins[login].Name); expired == nil || expired.MaxAge >= 0 || len(response.Cookies()) != 2 {
			t.Fatalf("%s changed %v", want, response.Cookies())
		}
	}
}

func TestLongRedirect(t *testing.T) {
	auth, provider := newTestAuth(t)
	for redirectTarget, want := range map[string]string{
		"/" + strings.Repeat("a", 2000):  "/" + strings.Repeat("a", 2000),
		"/" + strings.Repeat("a&", 3000): "/",
	} {
		response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath+"?rd="+url.QueryEscape(redirectTarget), userCertificate), userCertificate)
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != want {
			t.Fatalf("redirect of %d bytes: %d, location of %d bytes", len(redirectTarget), response.StatusCode, len(response.Header.Get("Location")))
		}
	}

	kept := 0
	for length := 2800; length < 3000; length++ {
		redirectTarget := "/" + strings.Repeat("a", length)
		switch response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath+"?rd="+redirectTarget, userCertificate), userCertificate); response.Header.Get("Location") {
		case redirectTarget:
			kept++
		case "/":
		default:
			t.Fatalf("redirect of %d bytes: %d", len(redirectTarget), response.StatusCode)
		}
	}
	if kept == 0 || kept == 200 {
		t.Fatalf("kept %d of 200 redirects near the cookie limit", kept)
	}
}

func TestCallbackNeedsItsPendingLogin(t *testing.T) {
	auth, provider := newTestAuth(t)
	first, second := get(t, auth, loginPath, userCertificate), get(t, auth, loginPath, userCertificate)
	callback := provider.approveLogin(first.Header.Get("Location"))

	for name, cookies := range map[string][]*http.Cookie{
		"another browser":       nil,
		"another pending login": {pendingLoginCookie(second)},
	} {
		if response := get(t, auth, callback, userCertificate, cookies...); response.StatusCode != http.StatusBadRequest || cookieNamed(response, sessionCookieName) != nil {
			t.Fatalf("%s: %d", name, response.StatusCode)
		}
	}
	if response := get(t, auth, callbackPath+"?code=x", userCertificate, pendingLoginCookie(first)); response.StatusCode != http.StatusBadRequest {
		t.Fatalf("without state: %d", response.StatusCode)
	}
	for range 20 {
		login := get(t, auth, loginPath, userCertificate)
		tampered := *pendingLoginCookie(login)
		tampered.Value = tamper(tampered.Value)
		if response := get(t, auth, provider.approveLogin(login.Header.Get("Location")), userCertificate, &tampered); response.StatusCode < http.StatusBadRequest || cookieNamed(response, sessionCookieName) != nil {
			t.Fatalf("tampered login cookie: %d", response.StatusCode)
		}
	}

	session := cookieNamed(get(t, auth, callback, userCertificate, pendingLoginCookie(first)), sessionCookieName)
	if response := get(t, auth, callback, userCertificate, session); session == nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback: %d", response.StatusCode)
	}
}

func TestLoginFailsAtIdentityProvider(t *testing.T) {
	auth, provider := newTestAuth(t)
	response := get(t, auth, loginPath, userCertificate)
	state := must(url.Parse(response.Header.Get("Location"))).Query().Get("state")
	if response := get(t, auth, callbackPath+"?error=access_denied&state="+state, userCertificate, pendingLoginCookie(response)); response.StatusCode != http.StatusForbidden {
		t.Fatalf("error from the identity provider: %d", response.StatusCode)
	}

	provider.down = true
	if response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath, userCertificate), userCertificate); response.StatusCode != http.StatusBadGateway || cookieNamed(response, sessionCookieName) != nil {
		t.Fatalf("identity provider down: %d", response.StatusCode)
	}
}

func TestLoginNeedsPKCE(t *testing.T) {
	auth, provider := newTestAuth(t)
	attacker := must(url.Parse(provider.approveLogin(get(t, auth, loginPath, userCertificate).Header.Get("Location")))).Query()
	victim := get(t, auth, loginPath, userCertificate)
	query := must(url.Parse(victim.Header.Get("Location"))).Query()
	provider.user.Nonce = query.Get("nonce")

	response := get(t, auth, callbackPath+"?"+url.Values{"code": {attacker.Get("code")}, "state": {query.Get("state")}}.Encode(), userCertificate, pendingLoginCookie(victim))
	if response.StatusCode != http.StatusForbidden || cookieNamed(response, sessionCookieName) != nil {
		t.Fatalf("code of another login: %d", response.StatusCode)
	}
}

func TestLoginRejects(t *testing.T) {
	tests := map[string]struct {
		uri    string
		change func(*fakePocketID)
	}{
		"nonce does not match": {userCertificate, func(fake *fakePocketID) { fake.user.Nonce = "other" }},
		"no subject":           {userCertificate, func(fake *fakePocketID) { fake.user.Subject = "" }},
		"no passkey":           {userCertificate, func(fake *fakePocketID) { fake.user.AuthenticationMethods = []string{"pwd"} }},
		"login older than an hour": {userCertificate, func(fake *fakePocketID) {
			fake.user.AuthenticatedAt = fake.now().Add(-maxAuthenticationAge - time.Second).Unix()
		}},
		"certificate of another user": {otherUserCertificate, func(*fakePocketID) {}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			auth, provider := newTestAuth(t)
			test.change(provider)
			response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath, test.uri), test.uri)
			if response.StatusCode != http.StatusForbidden || cookieNamed(response, sessionCookieName) != nil || pendingLoginCookie(response) != nil || response.Header.Get("Location") != "" {
				t.Fatalf("%d %s %v", response.StatusCode, response.Header.Get("Location"), response.Cookies())
			}
		})
	}
}

func TestRedirectsOnlyToLocalPaths(t *testing.T) {
	auth, provider := newTestAuth(t)
	for redirectTarget, want := range map[string]string{
		"/page?x=1&y=2":           "/page?x=1&y=2",
		"":                        "/",
		"page":                    "/",
		"https://evil.example":    "/",
		"//evil.example":          "/",
		`/\evil.example`:          "/",
		`\\evil.example`:          "/",
		"/page\r\nSet-Cookie: x":  "/",
		"/page\tx":                "/",
		"javascript:alert(1)":     "/",
		"https://" + host + "/ok": "/",
	} {
		response := completeLoginAtProvider(t, auth, provider, get(t, auth, loginPath+"?rd="+url.QueryEscape(redirectTarget), userCertificate), userCertificate)
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != want {
			t.Fatalf("rd %q: %d %q", redirectTarget, response.StatusCode, response.Header.Get("Location"))
		}
	}
}

func TestLogout(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)

	for name, header := range map[string][2]string{
		"cross site":        {"Sec-Fetch-Site", "cross-site"},
		"same site":         {"Sec-Fetch-Site", "same-site"},
		"another host":      {"Origin", "https://evil.example"},
		"another port":      {"Origin", "https://" + host + ":8443"},
		"another subdomain": {"Origin", "https://other.castelnuovo.eu"},
	} {
		request := newHTTPRequest(http.MethodPost, logoutPath, userCertificate, session)
		request.Header.Set(header[0], header[1])
		if response := serve(t, auth, request); response.StatusCode != http.StatusForbidden || len(response.Cookies()) != 0 {
			t.Fatalf("%s: %d %v", name, response.StatusCode, response.Cookies())
		}
	}

	var hint string
	for name, cookies := range map[string][]*http.Cookie{
		"with session":    {session},
		"without session": nil,
		"invalid session": {{Name: sessionCookieName, Value: "invalid"}},
	} {
		request := newHTTPRequest(http.MethodPost, logoutPath, userCertificate, cookies...)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		response := serve(t, auth, request)
		location := must(url.Parse(response.Header.Get("Location")))
		query, expired := location.Query(), cookieNamed(response, sessionCookieName)
		if response.StatusCode != http.StatusSeeOther || location.Scheme+"://"+location.Host+location.Path != issuer+"/api/oidc/end-session" || query.Get("post_logout_redirect_uri") != "https://"+host+"/" || query.Get("client_id") != clientID || expired == nil || expired.MaxAge >= 0 {
			t.Fatalf("%s: %d %s %v", name, response.StatusCode, location, response.Cookies())
		}
		if (name == "with session") != query.Has("id_token_hint") {
			t.Fatalf("%s: hint %q", name, query.Get("id_token_hint"))
		}
		if name == "with session" {
			hint = query.Get("id_token_hint")
		}
	}
	if hint != provider.lastIDToken {
		t.Fatalf("hint %q is not the ID token", hint)
	}
}

func TestLogoutEndsSessionImmediately(t *testing.T) {
	auth, provider := newTestAuth(t)
	session := logIn(t, auth, provider, userCertificate)
	if response := serve(t, auth, newHTTPRequest(http.MethodPost, logoutPath, userCertificate, session)); response.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", response.StatusCode)
	}
	if response := get(t, auth, "/page", userCertificate, session); response.StatusCode != http.StatusFound {
		t.Fatalf("copied cookie after logout: %d", response.StatusCode)
	}
}

func TestSessionStoreRemovesExpiredSessions(t *testing.T) {
	store := newSessionStore()
	now := time.Now()
	expired := store.add(session{expiresAt: now.Add(time.Minute)}, now)
	current := store.add(session{expiresAt: now.Add(2 * time.Hour)}, now.Add(time.Hour))
	if _, found := store.get(expired); found {
		t.Fatal("expired session kept")
	}
	if _, found := store.get(current); !found {
		t.Fatal("current session removed")
	}
}

func TestExpireCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	expireCookie(recorder, sessionCookieName)
	if got := recorder.Header().Get("Set-Cookie"); got != "__Host-castelnuovo=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" {
		t.Fatalf("Set-Cookie %q", got)
	}
}

func TestLogs(t *testing.T) {
	auth, provider := newTestAuth(t)
	core, logs := observer.New(zap.InfoLevel)
	auth.log = zap.New(core)

	session := logIn(t, auth, provider, userCertificate)
	get(t, auth, "/page", otherYubikeyCertificate, session)
	serve(t, auth, newHTTPRequest(http.MethodPost, logoutPath, userCertificate, session))
	for _, message := range []string{"user logged in", "session used from another host or certificate", "user logged out"} {
		entries := logs.FilterMessage(message).All()
		if len(entries) != 1 || entries[0].ContextMap()["client_ip"] != clientIP || entries[0].ContextMap()["sub"] != userID || entries[0].ContextMap()["host"] != host {
			t.Fatalf("%q: %v", message, entries)
		}
	}

	response := get(t, auth, loginPath, userCertificate)
	state := must(url.Parse(response.Header.Get("Location"))).Query().Get("state")
	get(t, auth, callbackPath+"?error=%3Cscript%3E&state="+state, userCertificate, pendingLoginCookie(response))
	denied := logs.FilterMessage("request denied").All()
	if len(denied) != 1 || denied[0].ContextMap()["idp_error"] != "<script>" || strings.Contains(fmt.Sprint(denied[0].ContextMap()["error"]), "script") {
		t.Fatalf("request denied: %v", denied)
	}
}
