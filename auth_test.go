package castelnuovo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
)

const (
	sub       = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	cert      = "spiffe://castelnuovo.eu/yubikey/87654321/owner/" + sub
	otherCert = "spiffe://castelnuovo.eu/yubikey/12345678/owner/11111111-2222-3333-4444-555555555555"
	machine   = "spiffe://castelnuovo.eu/client/backup"
	host      = "app.castelnuovo.eu"
	clientIP  = "203.0.113.7"
)

type fakePocketID struct {
	claims      claims
	exchanges   int
	exchangeErr error
	refreshes   int
	refreshErr  error
	onRefresh   func()
}

func (f *fakePocketID) authURL(redirectURL, state, nonce, _ string, reauth bool) string {
	query := url.Values{"redirect_uri": {redirectURL}, "state": {state}, "code": {nonce}}
	if reauth {
		query.Set("prompt", "login")
	}
	return "https://id.castelnuovo.eu/authorize?" + query.Encode()
}

func (f *fakePocketID) exchange(_ context.Context, _, code, _ string) (*claims, string, error) {
	f.exchanges++
	if f.exchangeErr != nil {
		return nil, "", f.exchangeErr
	}
	c := f.claims
	if c.Nonce == "" {
		c.Nonce = code
	}
	c.idToken = "id-token"
	return &c, "refresh-token", nil
}

func (f *fakePocketID) refresh(ctx context.Context, _ string) (*claims, string, error) {
	f.refreshes++
	if f.onRefresh != nil {
		f.onRefresh()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if f.refreshErr != nil {
		return nil, "", f.refreshErr
	}
	c := f.claims
	c.idToken = "refreshed-id-token"
	return &c, "refresh-token", nil
}

func (f *fakePocketID) logoutURL(idToken, redirectURL string) string {
	return "https://id.castelnuovo.eu/api/oidc/end-session?" + url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {redirectURL}}.Encode()
}

func newTest() (*Auth, *fakePocketID) {
	idp := &fakePocketID{claims: claims{
		Subject:           sub,
		PreferredUsername: "luca",
		Name:              "Luca Castelnuovo",
		Email:             "luca@example.com",
		Groups:            []string{"admins", "users"},
		AMR:               []string{"phr"},
		AuthTime:          time.Now().Unix(),
	}}
	return &Auth{store: newStore(), idp: idp, now: time.Now, log: zap.NewNop()}, idp
}

func request(method, target, uri string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	if uri != "" {
		u, _ := url.Parse(uri)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	}
	req.Header.Set("X-Auth-User", "spoofed")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: clientIP}))
}

func serve(s *Auth, req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		maps.Copy(w.Header(), r.Header)
		return nil
	})
	if err := s.ServeHTTP(rec, req, app); err != nil {
		herr, ok := errors.AsType[caddyhttp.HandlerError](err)
		if !ok {
			panic(err)
		}
		rec.WriteHeader(herr.StatusCode)
	}
	return rec.Result()
}

func get(s *Auth, path, uri string, cookies ...*http.Cookie) *http.Response {
	return serve(s, request(http.MethodGet, path, uri, cookies...))
}

func cookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func pending(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, loginCookie) && c.MaxAge > 0 {
			return c
		}
	}
	return nil
}

func finishLogin(s *Auth, resp *http.Response, uri string, cookies ...*http.Cookie) *http.Response {
	location, _ := url.Parse(resp.Header.Get("Location"))
	state := location.Query().Get("state")
	return get(s, "/.castelnuovo/callback?code="+location.Query().Get("code")+"&state="+state, uri, append(cookies, cookie(resp, loginCookie+state))...)
}

func logIn(t *testing.T, s *Auth, uri string) *http.Response {
	t.Helper()
	return finishLogin(s, get(s, "/.castelnuovo/login?rd=%2Fpage", uri), uri)
}

func TestLogin(t *testing.T) {
	s, _ := newTest()

	resp := get(s, "/page", cert)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/.castelnuovo/login?rd=%2Fpage" {
		t.Fatalf("without session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = logIn(t, s, cert)
	session := cookie(resp, sessionCookie)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/page" || session == nil {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = get(s, "/page", cert, session, &http.Cookie{Name: "app", Value: "kept"})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Auth-User") != "luca" || resp.Header.Get("X-Auth-Sub") != sub || resp.Header.Get("X-Auth-Name") != "Luca Castelnuovo" {
		t.Fatalf("with session: %d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("X-Auth-Email") != "luca@example.com" || resp.Header.Get("X-Auth-Groups") != "admins,users" {
		t.Fatalf("with session: %v", resp.Header)
	}
	if resp.Header.Get("Cookie") != "app=kept" {
		t.Fatalf("app received cookies %q", resp.Header.Get("Cookie"))
	}
}

func TestLoginRejects(t *testing.T) {
	tests := map[string]struct {
		uri    string
		change func(*claims)
	}{
		"certificate of another user":                   {otherCert, func(*claims) {}},
		"certificate of another user without a passkey": {otherCert, func(c *claims) { c.AMR = nil }},
		"nonce does not match":                          {cert, func(c *claims) { c.Nonce = "other" }},
		"no subject":                                    {cert, func(c *claims) { c.Subject = "" }},
		"no passkey":                                    {cert, func(c *claims) { c.AMR = []string{"otp"} }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, idp := newTest()
			tt.change(&idp.claims)
			if resp := logIn(t, s, tt.uri); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

func TestOldLoginAsksAgain(t *testing.T) {
	s, idp := newTest()
	fresh := idp.claims.AuthTime
	idp.claims.AuthTime = time.Now().Add(-2 * time.Hour).Unix()

	first := logIn(t, s, cert)
	location, _ := url.Parse(first.Header.Get("Location"))
	if first.StatusCode != http.StatusFound || location.Query().Get("prompt") != "login" || cookie(first, sessionCookie) != nil {
		t.Fatalf("first login: %d %s", first.StatusCode, location)
	}
	if resp := finishLogin(s, first, cert); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("new login that is still too old: %d", resp.StatusCode)
	}

	first = logIn(t, s, cert)
	idp.claims.AuthTime = fresh
	if resp := finishLogin(s, first, cert); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/page" || cookie(resp, sessionCookie) == nil {
		t.Fatalf("new login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestCallbackNeedsItsOwnLogin(t *testing.T) {
	s, idp := newTest()
	resp := get(s, "/.castelnuovo/login", cert)
	location, _ := url.Parse(resp.Header.Get("Location"))
	state := location.Query().Get("state")
	callback := "/.castelnuovo/callback?code=" + location.Query().Get("code") + "&state=" + state
	login := cookie(resp, loginCookie+state)

	if resp := get(s, callback, cert); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("without login cookie: %d", resp.StatusCode)
	}
	if resp := get(s, "/.castelnuovo/callback?code=c&state=other", cert, login); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("with another state: %d", resp.StatusCode)
	}
	if resp := get(s, callback, cert, &http.Cookie{Name: login.Name, Value: "forged"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("with a forged login cookie: %d", resp.StatusCode)
	}
	if resp := get(s, "/.castelnuovo/callback?error=access_denied&state="+state, cert, login); resp.StatusCode != http.StatusForbidden || idp.exchanges != 0 {
		t.Fatalf("with an error from the identity provider: %d, %d exchanges", resp.StatusCode, idp.exchanges)
	}
	if resp := get(s, callback, otherCert, login); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("with another certificate: %d", resp.StatusCode)
	}

	done := get(s, callback, cert, login)
	if deleted := cookie(done, login.Name); done.StatusCode != http.StatusFound || deleted == nil || deleted.MaxAge >= 0 {
		t.Fatalf("callback keeps the login cookie: %d", done.StatusCode)
	}
	if resp := get(s, callback, cert); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("used twice: %d", resp.StatusCode)
	}
	if resp := get(s, callback, cert, cookie(done, sessionCookie)); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("used twice with a session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestConcurrentLogins(t *testing.T) {
	s, _ := newTest()
	first := get(s, "/.castelnuovo/login?rd=%2Fone", cert)
	second := get(s, "/.castelnuovo/login?rd=%2Ftwo", cert, pending(first))

	if resp := finishLogin(s, first, cert, pending(second)); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/one" {
		t.Fatalf("first login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := finishLogin(s, second, cert); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/two" {
		t.Fatalf("second login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestPendingLoginsAreLimited(t *testing.T) {
	s, _ := newTest()
	var logins []*http.Cookie
	for range maxPendingLogins {
		resp := get(s, loginPath, cert, logins...)
		if len(resp.Cookies()) != 1 {
			t.Fatalf("login %d changed %d cookies", len(logins)+1, len(resp.Cookies()))
		}
		logins = append(logins, pending(resp))
	}

	resp := get(s, loginPath, cert, logins...)
	for _, login := range logins {
		if deleted := cookie(resp, login.Name); deleted == nil || deleted.MaxAge >= 0 {
			t.Fatalf("%s was kept", login.Name)
		}
	}
	if pending(resp) == nil {
		t.Fatal("no new login")
	}
}

func TestLongRedirect(t *testing.T) {
	s, _ := newTest()
	query := "/p?" + strings.Repeat("&a=b", 400)
	for rd, want := range map[string]string{
		query:                           query,
		"/" + strings.Repeat("a", 5000): "/",
	} {
		resp := get(s, "/.castelnuovo/login?rd="+url.QueryEscape(rd), cert)
		if login := pending(resp); len(login.Name)+len(login.Value) > maxCookieSize {
			t.Fatalf("rd of %d bytes: login cookie has %d bytes", len(rd), len(login.Name)+len(login.Value))
		}
		if resp := finishLogin(s, resp, cert); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
			t.Fatalf("rd of %d bytes: %d, Location of %d bytes", len(rd), resp.StatusCode, len(resp.Header.Get("Location")))
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	tests := map[string]struct {
		uri    string
		cookie *http.Cookie
		status int
	}{
		"no certificate":            {"", session, http.StatusForbidden},
		"machine certificate":       {machine, session, http.StatusForbidden},
		"certificate without owner": {"spiffe://castelnuovo.eu/yubikey/87654321", session, http.StatusForbidden},
		"old URI format":            {"https://pki.castelnuovo.eu#yubikey-87654321@" + sub, session, http.StatusForbidden},
		"another certificate":       {otherCert, session, http.StatusFound},
		"forged cookie":             {cert, &http.Cookie{Name: sessionCookie, Value: "forged"}, http.StatusFound},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if resp := get(s, "/page", tt.uri, tt.cookie); resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}

	req := request(http.MethodGet, "/page", cert, session)
	req.Host = "other.castelnuovo.eu"
	if resp := serve(s, req); resp.StatusCode != http.StatusFound {
		t.Fatalf("another host: %d", resp.StatusCode)
	}

	for _, path := range []string{loginPath, callbackPath, logoutPath} {
		if resp := get(s, path, machine); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with a machine certificate: %d", path, resp.StatusCode)
		}
	}
}

func TestChallenge(t *testing.T) {
	s, _ := newTest()
	tests := map[string]struct {
		method, mode string
		status       int
	}{
		"page load":              {http.MethodGet, "navigate", http.StatusFound},
		"without fetch metadata": {http.MethodGet, "", http.StatusFound},
		"fetch":                  {http.MethodGet, "cors", http.StatusUnauthorized},
		"websocket":              {http.MethodGet, "websocket", http.StatusUnauthorized},
		"form post":              {http.MethodPost, "navigate", http.StatusUnauthorized},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := request(tt.method, "/page", cert)
			if tt.mode != "" {
				req.Header.Set("Sec-Fetch-Mode", tt.mode)
			}
			if resp := serve(s, req); resp.StatusCode != tt.status || len(resp.Cookies()) != 0 {
				t.Fatalf("status %d, want %d, cookies %v", resp.StatusCode, tt.status, resp.Cookies())
			}
		})
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _ := newTest()
	for path, allow := range map[string]string{loginPath: http.MethodGet, callbackPath: http.MethodGet, logoutPath: http.MethodPost} {
		method := http.MethodPost
		if allow == http.MethodPost {
			method = http.MethodGet
		}
		if resp := serve(s, request(method, path, cert)); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != allow {
			t.Fatalf("%s %s: %d, Allow %q", method, path, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
}

func TestRewrittenRequest(t *testing.T) {
	s, _ := newTest()
	rewritten := func(original, target string) *http.Request {
		req := request(http.MethodGet, target, cert)
		u, _ := url.Parse(original)
		return req.WithContext(context.WithValue(req.Context(), caddyhttp.OriginalRequestCtxKey, http.Request{URL: u}))
	}

	if resp := serve(s, rewritten("/app/page?x=1", "/page?x=1")); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/.castelnuovo/login?rd=%2Fapp%2Fpage%3Fx%3D1" {
		t.Fatalf("stripped prefix: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := serve(s, rewritten("/secret", loginPath)); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/.castelnuovo/login?rd=%2Fsecret" {
		t.Fatalf("rewritten to the login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp := finishLogin(s, serve(s, rewritten(loginPath+"?rd=%2Fapp%2Fpage", "/page")), cert)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/app/page" {
		t.Fatalf("login rewritten to the app: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRefreshEndsSession(t *testing.T) {
	tests := map[string]func(*fakePocketID){
		"user disabled": func(f *fakePocketID) { f.refreshErr = errors.New("invalid_grant") },
		"another user":  func(f *fakePocketID) { f.claims.Subject = "someone-else" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s, idp := newTest()
			session := cookie(logIn(t, s, cert), sessionCookie)

			change(idp)
			later := time.Now().Add(refreshInterval + time.Minute)
			s.now = func() time.Time { return later }

			if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
				t.Fatalf("status %d", resp.StatusCode)
			}
			idp.refreshErr = nil
			if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
				t.Fatalf("after the refresh works again: %d", resp.StatusCode)
			}
		})
	}
}

func TestUnavailableIdentityProviderKeepsSession(t *testing.T) {
	s, idp := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	idp.refreshErr = fmt.Errorf("%w: connection refused", errUnavailable)
	now := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return now }
	for range 2 {
		if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("while unavailable: %d", resp.StatusCode)
		}
	}
	if idp.refreshes != 1 {
		t.Fatalf("refreshed %d times while unavailable", idp.refreshes)
	}

	idp.refreshErr = nil
	now = now.Add(retryInterval)
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("after recovery: %d", resp.StatusCode)
	}

	idp.refreshErr = fmt.Errorf("%w: internal server error", errUnavailable)
	now = now.Add(refreshInterval)
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("while unavailable again: %d", resp.StatusCode)
	}
	now = now.Add(maxOutage)
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("after a long outage: %d", resp.StatusCode)
	}
	idp.refreshErr = nil
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("after a long outage ended the session: %d", resp.StatusCode)
	}

	idp.exchangeErr = fmt.Errorf("%w: connection refused", errUnavailable)
	if resp := logIn(t, s, cert); resp.StatusCode != http.StatusBadGateway || cookie(resp, sessionCookie) != nil {
		t.Fatalf("login while unavailable: %d", resp.StatusCode)
	}
}

func TestCancelledRequestKeepsSession(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	serve(s, request(http.MethodGet, "/page", cert, session).WithContext(ctx))

	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("after a cancelled request: %d", resp.StatusCode)
	}
}

func TestRefreshLocksOnlyItsSession(t *testing.T) {
	s, idp := newTest()
	refreshing := cookie(logIn(t, s, cert), sessionCookie)
	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	other := cookie(logIn(t, s, cert), sessionCookie)

	entered, release := make(chan struct{}, 5), make(chan struct{})
	idp.onRefresh = func() {
		entered <- struct{}{}
		<-release
	}
	statuses := make(chan int)
	for range 5 {
		go func() { statuses <- get(s, "/page", cert, refreshing).StatusCode }()
	}

	timeout := time.After(5 * time.Second)
	select {
	case <-entered:
	case <-timeout:
		t.Fatal("refresh did not start")
	}

	done := make(chan int)
	go func() { done <- get(s, "/page", cert, other).StatusCode }()
	select {
	case status := <-done:
		if status != http.StatusOK {
			t.Fatalf("other session: %d", status)
		}
	case <-timeout:
		t.Fatal("other session waits for the refresh")
	}

	close(release)
	for range 5 {
		if status := <-statuses; status != http.StatusOK {
			t.Fatalf("refreshing session: %d", status)
		}
	}
	if len(entered) != 0 {
		t.Fatalf("refreshed %d more times", len(entered))
	}
}

func TestLogout(t *testing.T) {
	s, idp := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	req := request(http.MethodPost, "/.castelnuovo/logout", cert)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := serve(s, req); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("cross-site POST: %d", resp.StatusCode)
	}

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d", resp.StatusCode)
	}

	resp := serve(s, request(http.MethodPost, "/.castelnuovo/logout", cert, session))
	if cleared := cookie(resp, sessionCookie); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != idp.logoutURL("refreshed-id-token", "https://"+host+"/") || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("POST: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
	if resp := serve(s, request(http.MethodPost, "/.castelnuovo/logout", cert, session)); resp.Header.Get("Location") != idp.logoutURL("", "https://"+host+"/") {
		t.Fatalf("POST without a session: %s", resp.Header.Get("Location"))
	}
}

func TestLogoutDuringRefresh(t *testing.T) {
	s, idp := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)
	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }

	entered, release := make(chan struct{}, 1), make(chan struct{})
	idp.onRefresh = func() {
		entered <- struct{}{}
		<-release
	}
	refreshing, waiting, logout := make(chan int), make(chan int), make(chan *http.Response)
	go func() { refreshing <- get(s, "/page", cert, session).StatusCode }()
	<-entered
	go func() { waiting <- get(s, "/page", cert, session).StatusCode }()
	go func() { logout <- serve(s, request(http.MethodPost, logoutPath, cert, session)) }()
	for deadline := time.Now().Add(5 * time.Second); s.store.get(session.Value) != nil; runtime.Gosched() {
		if time.Now().After(deadline) {
			t.Fatal("logout did not remove the session")
		}
	}
	close(release)

	if status := <-refreshing; status != http.StatusOK {
		t.Fatalf("request that started the refresh: %d", status)
	}
	if status := <-waiting; status != http.StatusFound {
		t.Fatalf("request that waited for the refresh: %d", status)
	}
	if resp := <-logout; resp.Header.Get("Location") != idp.logoutURL("refreshed-id-token", "https://"+host+"/") {
		t.Fatalf("logout: %s", resp.Header.Get("Location"))
	}
}

func TestRemovesSpoofedHeaders(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	req := request(http.MethodGet, "/page", cert, session)
	req.Header.Set("X_Auth_User", "spoofed")
	if resp := serve(s, req); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Auth-User") != "luca" || resp.Header.Get("X_Auth_User") != "" {
		t.Fatalf("app received %v", resp.Header)
	}

	req = request(http.MethodGet, "/page", "", session)
	req.Header.Set("X_Auth_User", "spoofed")
	if resp := serve(s, req); resp.StatusCode != http.StatusForbidden || req.Header.Get("X_Auth_User") != "" || req.Header.Get("X-Auth-User") != "" || req.Header.Get("Cookie") != "" {
		t.Fatalf("denied request kept %v", req.Header)
	}
}

func TestKeepsAppCookies(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	req := request(http.MethodGet, "/page", cert)
	req.Header.Add("Cookie", `prefs={"theme":"dark"}; `+session.Name+"="+session.Value+`; name=café; path=a\b`)
	req.Header.Add("Cookie", loginCookie+"STATE=pending; spaced=a b; __Host-castelnuovo-login=old")
	want := `prefs={"theme":"dark"}; name=café; path=a\b; spaced=a b`
	if resp := serve(s, req); resp.StatusCode != http.StatusOK || resp.Header.Get("Cookie") != want {
		t.Fatalf("app received %d %q", resp.StatusCode, resp.Header.Get("Cookie"))
	}
}

func TestSessionExpires(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	later := time.Now().Add(sessionLifetime + time.Minute)
	s.now = func() time.Time { return later }

	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestStoreRemovesExpiredSessions(t *testing.T) {
	st := newStore()
	now := time.Now()
	expired := st.add(&session{expiresAt: now.Add(time.Minute)}, now)
	current := st.add(&session{expiresAt: now.Add(2 * time.Hour)}, now.Add(time.Hour))
	if st.get(expired) != nil || st.get(current) == nil {
		t.Fatalf("store has %d sessions", len(st.sessions))
	}
}

func TestNoOpenRedirect(t *testing.T) {
	for _, rd := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "/\x00x", ""} {
		if isLocalPath(rd) {
			t.Fatalf("%q is treated as local", rd)
		}
	}

	s, _ := newTest()
	resp := finishLogin(s, get(s, "/.castelnuovo/login?rd="+url.QueryEscape("/\t/evil.example"), cert), cert)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestWithoutCertificate(t *testing.T) {
	s, _ := newTest()
	s.DisableClientCertificate = true

	resp := logIn(t, s, "")
	session := cookie(resp, sessionCookie)
	if resp.StatusCode != http.StatusFound || session == nil {
		t.Fatalf("login without a certificate: %d", resp.StatusCode)
	}

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	if resp := get(s, "/page", "", session); resp.StatusCode != http.StatusOK {
		t.Fatalf("verify after refresh: %d", resp.StatusCode)
	}

	s.DisableClientCertificate = false
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("site that requires a certificate: %d", resp.StatusCode)
	}
}

func TestLogs(t *testing.T) {
	s, _ := newTest()
	core, logs := observer.New(zap.InfoLevel)
	s.log = zap.New(core)

	session := cookie(logIn(t, s, cert), sessionCookie)
	get(s, "/page", otherCert, session)
	serve(s, request(http.MethodPost, logoutPath, cert, session))
	for _, message := range []string{"user logged in", "session used from another host or certificate", "user logged out"} {
		entries := logs.FilterMessage(message).All()
		if len(entries) != 1 || entries[0].ContextMap()["client_ip"] != clientIP || entries[0].ContextMap()["sub"] != sub {
			t.Fatalf("%q: %v", message, entries)
		}
	}

	resp := get(s, loginPath, cert)
	location, _ := url.Parse(resp.Header.Get("Location"))
	get(s, callbackPath+"?error=%3Cscript%3E&state="+location.Query().Get("state"), cert, pending(resp))
	denied := logs.FilterMessage("request denied").All()
	if len(denied) != 1 || denied[0].ContextMap()["idp_error"] != "<script>" || strings.Contains(fmt.Sprint(denied[0].ContextMap()["error"]), "script") {
		t.Fatalf("request denied: %v", denied)
	}
}

type tokenRequest struct {
	form           url.Values
	user, password string
}

type testIdP struct {
	*httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any
	status int
	omit   string
	tokens chan tokenRequest
}

func newIdP(t *testing.T) *testIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{key: key, tokens: make(chan tokenRequest, 10)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /api/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, password, _ := r.BasicAuth()
		p.tokens <- tokenRequest{r.PostForm, user, password}
		w.Header().Set("Content-Type", "application/json")
		if p.status != 0 {
			w.WriteHeader(p.status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		response := map[string]any{
			"access_token":  "access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"id_token":      p.sign(),
			"refresh_token": "new-refresh-token",
		}
		delete(response, p.omit)
		_ = json.NewEncoder(w).Encode(response)
	})
	p.Server = httptest.NewTLSServer(mux)
	t.Cleanup(p.Close)
	p.claims = map[string]any{
		"iss":       p.URL,
		"aud":       "client",
		"sub":       sub,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"nonce":     "nonce",
		"amr":       []string{"phr"},
		"auth_time": time.Now().Unix(),
		"groups":    []string{"admins"},
	}
	return p
}

func (p *testIdP) sign() string {
	payload, _ := json.Marshal(p.claims)
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, _ := rsa.SignPKCS1v15(nil, p.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (p *testIdP) client() *oidcClient {
	return newOIDC(p.URL, "client", "secret", p.Client())
}

func TestOIDCAuthURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", http.DefaultClient)
	verifier := oauth2.GenerateVerifier()
	for _, reauth := range []bool{false, true} {
		u, _ := url.Parse(o.authURL("https://"+host+callbackPath, "state", "nonce", verifier, reauth))
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
		if reauth {
			want.Set("prompt", "login")
		}
		if u.Scheme+"://"+u.Host+u.Path != issuer+"/authorize" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("reauth %v: %s", reauth, u)
		}
	}
}

func TestOIDCExchange(t *testing.T) {
	p := newIdP(t)
	c, refreshToken, err := p.client().exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
	if err != nil || c.Subject != sub || c.Nonce != "nonce" || !slices.Equal(c.AMR, []string{"phr"}) || !slices.Equal(c.Groups, []string{"admins"}) || c.idToken == "" || refreshToken != "new-refresh-token" {
		t.Fatalf("%v %+v %q", err, c, refreshToken)
	}

	req := <-p.tokens
	want := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code"},
		"code_verifier": {"verifier"},
		"redirect_uri":  {"https://" + host + callbackPath},
	}
	if req.user != "client" || req.password != "secret" || !maps.EqualFunc(req.form, want, slices.Equal[[]string]) {
		t.Fatalf("token request: %+v", req)
	}
}

func TestOIDCExchangeFails(t *testing.T) {
	tests := map[string]struct {
		change      func(*testIdP)
		requests    int
		unavailable bool
	}{
		"code rejected":    {func(p *testIdP) { p.status = http.StatusBadRequest }, 1, false},
		"server error":     {func(p *testIdP) { p.status = http.StatusServiceUnavailable }, 1, true},
		"rate limited":     {func(p *testIdP) { p.status = http.StatusTooManyRequests }, 1, true},
		"unreachable":      {func(p *testIdP) { p.Close() }, 0, true},
		"no ID token":      {func(p *testIdP) { p.omit = "id_token" }, 1, false},
		"no refresh token": {func(p *testIdP) { p.omit = "refresh_token" }, 1, false},
		"another audience": {func(p *testIdP) { p.claims["aud"] = "other" }, 1, false},
		"expired ID token": {func(p *testIdP) { p.claims["exp"] = time.Now().Add(-time.Hour).Unix() }, 1, false},
		"malformed claims": {func(p *testIdP) { p.claims["auth_time"] = "yesterday" }, 1, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := newIdP(t)
			o := p.client()
			tt.change(p)
			_, _, err := o.exchange(context.Background(), "https://"+host+callbackPath, "code", "verifier")
			if err == nil || errors.Is(err, errUnavailable) != tt.unavailable || len(p.tokens) != tt.requests {
				t.Fatalf("error %v after %d token requests", err, len(p.tokens))
			}
		})
	}
}

func TestOIDCRefresh(t *testing.T) {
	p := newIdP(t)
	o := p.client()

	p.omit = "refresh_token"
	c, refreshToken, err := o.refresh(context.Background(), "old-refresh-token")
	if err != nil || c.Subject != sub || refreshToken != "old-refresh-token" {
		t.Fatalf("%v %+v %q", err, c, refreshToken)
	}
	req := <-p.tokens
	want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"old-refresh-token"}}
	if req.user != "client" || req.password != "secret" || !maps.EqualFunc(req.form, want, slices.Equal[[]string]) {
		t.Fatalf("token request: %+v", req)
	}

	p.status = http.StatusBadRequest
	if _, _, err := o.refresh(context.Background(), "old-refresh-token"); err == nil || errors.Is(err, errUnavailable) {
		t.Fatalf("rejected refresh token: %v", err)
	}
	p.status = http.StatusBadGateway
	if _, _, err := o.refresh(context.Background(), "old-refresh-token"); !errors.Is(err, errUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

func TestOIDCLogoutURL(t *testing.T) {
	o := newOIDC(issuer, "client", "secret", http.DefaultClient)
	redirect := "https://" + host + "/"
	for idToken, want := range map[string]url.Values{
		"id-token": {"id_token_hint": {"id-token"}, "client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
		"":         {"client_id": {"client"}, "post_logout_redirect_uri": {redirect}},
	} {
		u, _ := url.Parse(o.logoutURL(idToken, redirect))
		if u.Scheme+"://"+u.Host+u.Path != issuer+"/api/oidc/end-session" || !maps.EqualFunc(u.Query(), want, slices.Equal[[]string]) {
			t.Fatalf("ID token %q: %s", idToken, u)
		}
	}
}
