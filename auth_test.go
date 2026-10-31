package castelnuovo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	sub          = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	yubikey      = "spiffe://castelnuovo.eu/yubikey/87654321/owner/" + sub
	otherYubikey = "spiffe://castelnuovo.eu/yubikey/12345678/owner/11111111-2222-3333-4444-555555555555"
	machine      = "spiffe://castelnuovo.eu/client/backup"
	host         = "app.castelnuovo.eu"
)

type fakePocketID struct {
	claims     claims
	refreshErr error
	onRefresh  func()
}

func (f *fakePocketID) authURL(redirectURL, state, nonce, _ string) string {
	f.claims.Nonce = nonce
	return "https://id.castelnuovo.eu/authorize?" + url.Values{"redirect_uri": {redirectURL}, "state": {state}}.Encode()
}

func (f *fakePocketID) exchange(context.Context, string, string, string) (*claims, string, error) {
	c := f.claims
	c.idToken = "id-token"
	return &c, "refresh-token", nil
}

func (f *fakePocketID) refresh(ctx context.Context, _ string) (*claims, string, error) {
	if f.onRefresh != nil {
		f.onRefresh()
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	c := f.claims
	c.idToken = "refreshed-id-token"
	return &c, "refresh-token", f.refreshErr
}

func (f *fakePocketID) logoutURL(idToken, redirectURL string) string {
	return "https://id.castelnuovo.eu/api/oidc/end-session?" + url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {redirectURL}}.Encode()
}

func newTest() (*Auth, *fakePocketID) {
	idp := &fakePocketID{claims: claims{
		Subject:           sub,
		PreferredUsername: "luca",
		Name:              "Luca Castelnuovo",
		Groups:            []string{"admins"},
		AMR:               []string{"phr"},
		AuthTime:          time.Now().Unix(),
	}}
	return &Auth{store: newStore(), idp: idp, now: time.Now, log: zap.NewNop()}, idp
}

func request(method, path, uri string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	if uri != "" {
		u, _ := url.Parse(uri)
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	}
	req.Header.Set("X-Auth-User", "spoofed")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
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

func logIn(t *testing.T, s *Auth, uri string) *http.Response {
	t.Helper()
	resp := get(s, "/.castelnuovo/login?rd=%2Fpage", uri)
	location, _ := url.Parse(resp.Header.Get("Location"))
	return get(s, "/.castelnuovo/callback?code=c&state="+location.Query().Get("state"), uri, cookie(resp, loginCookie))
}

func TestLogin(t *testing.T) {
	s, _ := newTest()

	resp := get(s, "/page", yubikey)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/.castelnuovo/login?rd=%2Fpage" {
		t.Fatalf("without session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = logIn(t, s, yubikey)
	session := cookie(resp, sessionCookie)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/page" || session == nil {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = get(s, "/page", yubikey, session, &http.Cookie{Name: "app", Value: "kept"})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Auth-User") != "luca" || resp.Header.Get("X-Auth-Sub") != sub || resp.Header.Get("X-Auth-Name") != "Luca Castelnuovo" {
		t.Fatalf("with session: %d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Cookie") != "app=kept" {
		t.Fatalf("app received cookies %q", resp.Header.Get("Cookie"))
	}
}

func TestLoginRejects(t *testing.T) {
	s, _ := newTest()
	if resp := logIn(t, s, otherYubikey); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("YubiKey of another user: %d", resp.StatusCode)
	}

	tests := map[string]func(*claims){
		"no passkey": func(c *claims) { c.AMR = []string{"otp"} },
		"passkey used too long ago": func(c *claims) {
			c.AuthTime = time.Now().Add(-2 * time.Hour).Unix()
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s, idp := newTest()
			change(&idp.claims)
			if resp := logIn(t, s, yubikey); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

func TestCallbackNeedsItsOwnLogin(t *testing.T) {
	s, _ := newTest()
	resp := get(s, "/.castelnuovo/login", yubikey)
	location, _ := url.Parse(resp.Header.Get("Location"))
	callback := "/.castelnuovo/callback?code=c&state=" + location.Query().Get("state")
	login := cookie(resp, loginCookie)

	if resp := get(s, callback, yubikey); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("without login cookie: %d", resp.StatusCode)
	}
	if resp := get(s, "/.castelnuovo/callback?code=c&state=other", yubikey, login); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("with another state: %d", resp.StatusCode)
	}
	if resp := get(s, callback, yubikey, &http.Cookie{Name: loginCookie, Value: "forged"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("with a forged login cookie: %d", resp.StatusCode)
	}
	if resp := get(s, callback, otherYubikey, login); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("with another YubiKey: %d", resp.StatusCode)
	}

	resp = get(s, callback, yubikey, login)
	if deleted := cookie(resp, loginCookie); resp.StatusCode != http.StatusFound || deleted == nil || deleted.MaxAge >= 0 {
		t.Fatalf("callback keeps the login cookie: %d", resp.StatusCode)
	}
	if resp := get(s, callback, yubikey); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("used twice: %d", resp.StatusCode)
	}
}

func TestVerifyRejects(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, yubikey), sessionCookie)

	tests := map[string]struct {
		uri    string
		cookie *http.Cookie
		status int
	}{
		"no certificate":        {"", session, http.StatusForbidden},
		"machine certificate":   {machine, session, http.StatusForbidden},
		"YubiKey without owner": {"spiffe://castelnuovo.eu/yubikey/87654321", session, http.StatusForbidden},
		"old URI format":        {"https://pki.castelnuovo.eu#yubikey-87654321@" + sub, session, http.StatusForbidden},
		"another YubiKey":       {otherYubikey, session, http.StatusFound},
		"forged cookie":         {yubikey, &http.Cookie{Name: sessionCookie, Value: "forged"}, http.StatusFound},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if resp := get(s, "/page", tt.uri, tt.cookie); resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}

	for _, path := range []string{loginPath, callbackPath, logoutPath} {
		if resp := get(s, path, machine); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with a machine certificate: %d", path, resp.StatusCode)
		}
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
			session := cookie(logIn(t, s, yubikey), sessionCookie)

			change(idp)
			later := time.Now().Add(refreshInterval + time.Minute)
			s.now = func() time.Time { return later }

			if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusFound {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
}

func TestCancelledRequestKeepsSession(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, yubikey), sessionCookie)

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	serve(s, request(http.MethodGet, "/page", yubikey, session).WithContext(ctx))

	if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("after a cancelled request: %d", resp.StatusCode)
	}
}

func TestRefreshLocksOnlyItsSession(t *testing.T) {
	s, idp := newTest()
	refreshing := cookie(logIn(t, s, yubikey), sessionCookie)
	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	other := cookie(logIn(t, s, yubikey), sessionCookie)

	entered, release := make(chan struct{}, 5), make(chan struct{})
	idp.onRefresh = func() {
		entered <- struct{}{}
		<-release
	}
	statuses := make(chan int)
	for range 5 {
		go func() { statuses <- get(s, "/page", yubikey, refreshing).StatusCode }()
	}

	timeout := time.After(5 * time.Second)
	select {
	case <-entered:
	case <-timeout:
		t.Fatal("refresh did not start")
	}

	done := make(chan int)
	go func() { done <- get(s, "/page", yubikey, other).StatusCode }()
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
	session := cookie(logIn(t, s, yubikey), sessionCookie)

	if resp := get(s, "/.castelnuovo/logout", yubikey, session); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}

	req := request(http.MethodPost, "/.castelnuovo/logout", yubikey)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := serve(s, req); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("cross-site POST: %d", resp.StatusCode)
	}

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d", resp.StatusCode)
	}

	resp := serve(s, request(http.MethodPost, "/.castelnuovo/logout", yubikey, session))
	if cleared := cookie(resp, sessionCookie); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != idp.logoutURL("refreshed-id-token", "https://"+host+"/") || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("POST: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
	if resp := serve(s, request(http.MethodPost, "/.castelnuovo/logout", yubikey, session)); resp.Header.Get("Location") != idp.logoutURL("", "https://"+host+"/") {
		t.Fatalf("POST without a session: %s", resp.Header.Get("Location"))
	}
}

func TestRemovesSpoofedHeaders(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, yubikey), sessionCookie)

	req := request(http.MethodGet, "/page", yubikey, session)
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

func TestSessionExpires(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, yubikey), sessionCookie)

	later := time.Now().Add(sessionLifetime + time.Minute)
	s.now = func() time.Time { return later }

	if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestNoOpenRedirect(t *testing.T) {
	for _, rd := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "/\x00x", ""} {
		if isLocalPath(rd) {
			t.Fatalf("%q is treated as local", rd)
		}
	}

	s, _ := newTest()
	resp := get(s, "/.castelnuovo/login?rd="+url.QueryEscape("/\t/evil.example"), yubikey)
	location, _ := url.Parse(resp.Header.Get("Location"))
	resp = get(s, "/.castelnuovo/callback?code=c&state="+location.Query().Get("state"), yubikey, cookie(resp, loginCookie))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestWithoutYubikey(t *testing.T) {
	s, _ := newTest()
	s.DisableYubikey = true

	resp := logIn(t, s, "")
	session := cookie(resp, sessionCookie)
	if resp.StatusCode != http.StatusFound || session == nil {
		t.Fatalf("login without a YubiKey: %d", resp.StatusCode)
	}

	later := time.Now().Add(refreshInterval + time.Minute)
	s.now = func() time.Time { return later }
	if resp := get(s, "/page", "", session); resp.StatusCode != http.StatusOK {
		t.Fatalf("verify after refresh: %d", resp.StatusCode)
	}

	s.DisableYubikey = false
	if resp := get(s, "/page", yubikey, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("site that requires a YubiKey: %d", resp.StatusCode)
	}
}
