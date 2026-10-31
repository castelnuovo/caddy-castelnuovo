package castelnuovo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

func httpRequest(method, target, uri string, cookies ...*http.Cookie) *http.Request {
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
	return serve(s, httpRequest(http.MethodGet, path, uri, cookies...))
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
		change func(*fakePocketID)
	}{
		"certificate of another user":                   {otherCert, func(*fakePocketID) {}},
		"certificate of another user without a passkey": {otherCert, func(f *fakePocketID) { f.claims.AMR = nil }},
		"nonce does not match":                          {cert, func(f *fakePocketID) { f.claims.Nonce = "other" }},
		"no subject":                                    {cert, func(f *fakePocketID) { f.claims.Subject = "" }},
		"no passkey":                                    {cert, func(f *fakePocketID) { f.claims.AMR = []string{"otp"} }},
		"code rejected":                                 {cert, func(f *fakePocketID) { f.exchangeErr = errors.New("invalid_grant") }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, idp := newTest()
			tt.change(idp)
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

	req := httpRequest(http.MethodGet, "/page", cert, session)
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
			req := httpRequest(tt.method, "/page", cert)
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
		if resp := serve(s, httpRequest(method, path, cert)); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != allow {
			t.Fatalf("%s %s: %d, Allow %q", method, path, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
}

func TestRewrittenRequest(t *testing.T) {
	s, _ := newTest()
	rewritten := func(original, target string) *http.Request {
		req := httpRequest(http.MethodGet, target, cert)
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
	serve(s, httpRequest(http.MethodGet, "/page", cert, session).WithContext(ctx))

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

	req := httpRequest(http.MethodPost, "/.castelnuovo/logout", cert)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := serve(s, req); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("cross-site POST: %d", resp.StatusCode)
	}

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d", resp.StatusCode)
	}

	resp := serve(s, httpRequest(http.MethodPost, "/.castelnuovo/logout", cert, session))
	if cleared := cookie(resp, sessionCookie); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != idp.logoutURL("refreshed-id-token", "https://"+host+"/") || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("POST: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
	if resp := serve(s, httpRequest(http.MethodPost, "/.castelnuovo/logout", cert, session)); resp.Header.Get("Location") != idp.logoutURL("", "https://"+host+"/") {
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
	go func() { logout <- serve(s, httpRequest(http.MethodPost, logoutPath, cert, session)) }()
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

	req := httpRequest(http.MethodGet, "/page", cert, session)
	req.Header.Set("X_Auth_User", "spoofed")
	if resp := serve(s, req); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Auth-User") != "luca" || resp.Header.Get("X_Auth_User") != "" {
		t.Fatalf("app received %v", resp.Header)
	}

	req = httpRequest(http.MethodGet, "/page", "", session)
	req.Header.Set("X_Auth_User", "spoofed")
	if resp := serve(s, req); resp.StatusCode != http.StatusForbidden || req.Header.Get("X_Auth_User") != "" || req.Header.Get("X-Auth-User") != "" || req.Header.Get("Cookie") != "" {
		t.Fatalf("denied request kept %v", req.Header)
	}
}

func TestKeepsAppCookies(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	req := httpRequest(http.MethodGet, "/page", cert)
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
	serve(s, httpRequest(http.MethodPost, logoutPath, cert, session))
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
