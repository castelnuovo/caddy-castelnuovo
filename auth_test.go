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

func TestCertificateRejects(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)
	for name, uri := range map[string]string{
		"no certificate":            "",
		"machine certificate":       machine,
		"certificate without owner": "spiffe://castelnuovo.eu/yubikey/87654321",
		"old URI format":            "https://pki.castelnuovo.eu#yubikey-87654321@" + sub,
	} {
		for _, path := range []string{"/page", loginPath, callbackPath, logoutPath} {
			if resp := get(s, path, uri, session); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s on %s: %d", name, path, resp.StatusCode)
			}
		}
	}
}
