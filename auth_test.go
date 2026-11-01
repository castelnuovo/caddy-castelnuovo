package castelnuovo

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
)

const (
	sub       = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	otherSub  = "11111111-2222-3333-4444-555555555555"
	cert      = "spiffe://castelnuovo.eu/yubikey/87654321/owner/" + sub
	otherKey  = "spiffe://castelnuovo.eu/yubikey/12345678/owner/" + sub
	otherCert = "spiffe://castelnuovo.eu/yubikey/12345678/owner/" + otherSub
	host      = "app.castelnuovo.eu"
	clientID  = "5f0c2b8e-3d4a-4e6f-9a1b-7c8d9e0f1a2b"
	clientIP  = "203.0.113.7"
)

var errInvalidGrant = errors.New("invalid_grant")

type grant struct {
	authTime int64
	revoked  bool
}

type authorization struct {
	nonce, challenge, redirectURL string
	authTime                      int64
}

type issuedToken struct {
	grant     *grant
	rotatedAt time.Time
}

type fakePocketID struct {
	*oidcClient
	clock     atomic.Int64
	onRefresh func()

	mu          sync.Mutex
	user        claims
	down        bool
	disabled    bool
	refreshes   int
	endSessions int
	codes       map[string]authorization
	tokens      map[string]*issuedToken
	hints       map[string]*grant
	idTokens    map[string]time.Time
}

func (f *fakePocketID) now() time.Time {
	return time.Unix(0, f.clock.Load())
}

func (f *fakePocketID) advance(d time.Duration) {
	f.clock.Add(int64(d))
}

func (f *fakePocketID) authorize(location string) string {
	query := must(url.Parse(location)).Query()
	code := rand.Text()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = authorization{query.Get("nonce"), query.Get("code_challenge"), query.Get("redirect_uri"), f.now().Unix()}
	return query.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {query.Get("state")}}.Encode()
}

func (f *fakePocketID) exchange(_ context.Context, redirectURL, code, verifier string) (tokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.codes[code]
	delete(f.codes, code)
	switch {
	case f.down:
		return tokens{}, errUnavailable
	case !ok || a.redirectURL != redirectURL || a.challenge != oauth2.S256ChallengeFromVerifier(verifier):
		return tokens{}, errInvalidGrant
	}
	return f.issue(&grant{authTime: a.authTime}, a.nonce), nil
}

func (f *fakePocketID) refresh(ctx context.Context, refreshToken string) (tokens, error) {
	if f.onRefresh != nil {
		f.onRefresh()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	t, ok := f.tokens[refreshToken]
	switch {
	case ctx.Err() != nil:
		return tokens{}, fmt.Errorf("%w: %w", errUnavailable, ctx.Err())
	case f.down:
		return tokens{}, errUnavailable
	case !ok || t.grant.revoked || f.disabled:
		return tokens{}, errInvalidGrant
	case t.rotatedAt.IsZero():
		t.rotatedAt = f.now()
	case f.now().Sub(t.rotatedAt) > time.Minute:
		t.grant.revoked = true
		return tokens{}, errInvalidGrant
	}
	return f.issue(t.grant, ""), nil
}

func (f *fakePocketID) issue(g *grant, nonce string) tokens {
	now, c := f.now(), f.user
	if c.Nonce == "" {
		c.Nonce = nonce
	}
	if c.AuthTime == 0 {
		c.AuthTime = g.authTime
	}
	idClaims := map[string]any{
		"iss":                issuer,
		"aud":                clientID,
		"sub":                c.Subject,
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"type":               "id-token",
		"auth_time":          c.AuthTime,
		"amr":                c.AMR,
		"email":              c.Email,
		"email_verified":     true,
		"name":               c.Name,
		"given_name":         "Luca",
		"family_name":        "Castelnuovo",
		"preferred_username": c.PreferredUsername,
		"picture":            issuer + "/api/users/" + c.Subject + "/profile-picture.png",
		"groups":             c.Groups,
	}
	if c.Nonce != "" {
		idClaims["nonce"] = c.Nonce
	}
	t := tokens{
		idToken: fakeJWT(idClaims),
		refreshToken: fakeJWT(map[string]any{
			"iss":  issuer,
			"aud":  clientID,
			"sub":  c.Subject,
			"exp":  now.Add(30 * 24 * time.Hour).Unix(),
			"iat":  now.Unix(),
			"type": "oauth-refresh-token",
			"rt":   (rand.Text() + rand.Text())[:40],
		}),
	}
	t.claims = must(parseClaims(t.idToken))
	f.tokens[t.refreshToken] = &issuedToken{grant: g}
	f.hints[t.idToken] = g
	f.idTokens[t.idToken] = now.Add(time.Hour)
	return t
}

func (f *fakePocketID) verifyIDToken(_ context.Context, idToken string) (claims, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch expiry, ok := f.idTokens[idToken]; {
	case !ok:
		return claims{}, errors.New("ID token was not signed by the identity provider")
	case !f.now().Before(expiry):
		return claims{}, errors.New("ID token is expired")
	}
	return parseClaims(idToken)
}

func (f *fakePocketID) endSession(_ context.Context, idToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endSessions++
	if f.down {
		return errUnavailable
	}
	if g, ok := f.hints[idToken]; ok {
		g.revoked = true
	}
	return nil
}

func fakeJWT(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	signature := make([]byte, 256)
	_, _ = rand.Read(signature)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","kid":"3Ai6Wu_fJGPGTJp2ngs1qcXnWxNl0xr9s0yGfO4dLzI","typ":"JWT"}`)) + "." + enc(payload) + "." + enc(signature)
}

func tamper(value string) string {
	b := []byte(value)
	if b[len(b)/2] == 'A' {
		b[len(b)/2] = 'B'
	} else {
		b[len(b)/2] = 'A'
	}
	return string(b)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newTest(t *testing.T) (*Auth, *fakePocketID) {
	idp := &fakePocketID{
		oidcClient: newOIDC(issuer, clientID, "secret", nil),
		user: claims{
			Subject:           sub,
			PreferredUsername: "luca",
			Name:              "Luca Castelnuovo",
			Email:             "luca@castelnuovo.eu",
			Groups:            []string{"admins", "users"},
			AMR:               []string{"phr"},
		},
		codes:    map[string]authorization{},
		tokens:   map[string]*issuedToken{},
		hints:    map[string]*grant{},
		idTokens: map[string]time.Time{},
	}
	idp.clock.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	return newAuth(t, idp, "secret"), idp
}

func newAuth(t *testing.T, idp *fakePocketID, secret string) *Auth {
	aead, err := newAEAD(secret)
	if err != nil {
		t.Fatal(err)
	}
	return &Auth{aead: aead, idp: idp, now: idp.now, log: zap.NewNop()}
}

func httpRequest(method, target, uri string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	if uri != "" {
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{must(url.Parse(uri))}}}}}
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), nil, nil)
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, clientIP)
	return r
}

func serve(t *testing.T, m *Auth, r *http.Request) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		maps.Copy(w.Header(), r.Header)
		return nil
	})
	if err := m.ServeHTTP(rec, r, app); err != nil {
		if herr, ok := errors.AsType[caddyhttp.HandlerError](err); ok {
			rec.WriteHeader(herr.StatusCode)
		} else {
			t.Errorf("handler returned %v", err)
		}
	}
	resp := rec.Result()
	for _, line := range resp.Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil || len(line) > maxCookieSize || c.MaxAge == 0 || !strings.HasPrefix(c.Name, "__Host-") || c.Path != "/" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("unsafe cookie %q", line)
		}
	}
	return resp
}

func get(t *testing.T, m *Auth, target, uri string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	return serve(t, m, httpRequest(http.MethodGet, target, uri, cookies...))
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
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

func finishLogin(t *testing.T, m *Auth, idp *fakePocketID, login *http.Response, uri string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	return get(t, m, idp.authorize(login.Header.Get("Location")), uri, append(cookies, pending(login))...)
}

func logIn(t *testing.T, m *Auth, idp *fakePocketID, uri string) *http.Cookie {
	t.Helper()
	resp := finishLogin(t, m, idp, get(t, m, loginPath+"?rd=%2Fpage", uri), uri)
	session := cookieNamed(resp, sessionCookie)
	if resp.StatusCode != http.StatusFound || session == nil || session.MaxAge <= 0 {
		t.Fatalf("login: %d %v", resp.StatusCode, resp.Cookies())
	}
	return session
}

func TestProtectedRequest(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)

	req := httpRequest(http.MethodGet, "/page", cert, session, &http.Cookie{Name: "app", Value: "kept"}, &http.Cookie{Name: loginCookie + "STATE", Value: "x"}, &http.Cookie{Name: "__Host-castelnuovo-app", Value: "kept"})
	req.Header.Set("X-Auth-User", "spoofed")
	req.Header.Set("X-Auth-Admin", "spoofed")
	req.Header["X_Auth_Groups"] = []string{"spoofed"}
	req.Header["x_auth_role"] = []string{"spoofed"}
	resp := serve(t, m, req)
	if resp.StatusCode != http.StatusOK || len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("status %d, cookies %v", resp.StatusCode, resp.Cookies())
	}

	want := map[string]string{
		"X-Auth-Sub":    sub,
		"X-Auth-User":   "luca",
		"X-Auth-Name":   "Luca Castelnuovo",
		"X-Auth-Email":  "luca@castelnuovo.eu",
		"X-Auth-Groups": "admins,users",
		"Cookie":        "app=kept; __Host-castelnuovo-app=kept",
	}
	for name, value := range want {
		if got := resp.Header.Values(name); !slices.Equal(got, []string{value}) {
			t.Errorf("%s: %q, want %q", name, got, value)
		}
	}
	for name := range resp.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") && want[name] == "" {
			t.Errorf("app received %s", name)
		}
	}
}

func TestChallenge(t *testing.T) {
	m, _ := newTest(t)
	tests := map[string]struct {
		method, mode, dest string
		status             int
	}{
		"page load":              {http.MethodGet, "navigate", "document", http.StatusFound},
		"without fetch metadata": {http.MethodGet, "", "", http.StatusFound},
		"frame":                  {http.MethodGet, "navigate", "iframe", http.StatusUnauthorized},
		"fetch":                  {http.MethodGet, "cors", "empty", http.StatusUnauthorized},
		"websocket":              {http.MethodGet, "websocket", "websocket", http.StatusUnauthorized},
		"form post":              {http.MethodPost, "navigate", "document", http.StatusUnauthorized},
		"head":                   {http.MethodHead, "", "", http.StatusUnauthorized},
		"fetch without dest":     {http.MethodGet, "no-cors", "", http.StatusUnauthorized},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := httpRequest(tt.method, "/page?x=1", cert)
			req.Header.Set("Sec-Fetch-Mode", tt.mode)
			req.Header.Set("Sec-Fetch-Dest", tt.dest)
			resp := serve(t, m, req)
			if resp.StatusCode != tt.status || len(resp.Cookies()) != 0 {
				t.Fatalf("status %d, want %d, cookies %v", resp.StatusCode, tt.status, resp.Cookies())
			}
			if tt.status == http.StatusFound && resp.Header.Get("Location") != loginPath+"?rd=%2Fpage%3Fx%3D1" {
				t.Fatalf("redirected to %s", resp.Header.Get("Location"))
			}
		})
	}
}

func TestMethodNotAllowed(t *testing.T) {
	m, _ := newTest(t)
	for path, allow := range map[string]string{loginPath: http.MethodGet, callbackPath: http.MethodGet, logoutPath: http.MethodPost} {
		method := http.MethodPost
		if allow == http.MethodPost {
			method = http.MethodGet
		}
		if resp := serve(t, m, httpRequest(method, path, cert)); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != allow {
			t.Fatalf("%s %s: %d, Allow %q", method, path, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
}

func TestRoutesOnOriginalRequest(t *testing.T) {
	m, idp := newTest(t)
	rewritten := func(method, original, target string) *http.Request {
		req := httpRequest(method, original, cert)
		req.Method, req.URL, req.RequestURI = http.MethodGet, must(url.Parse(target)), target
		return req
	}

	if resp := serve(t, m, rewritten(http.MethodGet, "/app/page?x=1", "/page?x=1")); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != loginPath+"?rd=%2Fapp%2Fpage%3Fx%3D1" {
		t.Fatalf("stripped prefix: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := serve(t, m, rewritten(http.MethodGet, "/secret", loginPath)); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != loginPath+"?rd=%2Fsecret" || pending(resp) != nil {
		t.Fatalf("rewritten to the login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp := finishLogin(t, m, idp, serve(t, m, rewritten(http.MethodGet, loginPath+"?rd=%2Fapp%2Fpage", "/page")), cert)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/app/page" {
		t.Fatalf("login rewritten to the app: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := serve(t, m, rewritten(http.MethodPost, logoutPath, "/page")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout with a rewritten method: %d", resp.StatusCode)
	}
	crossSite := rewritten(http.MethodPost, logoutPath, "/page")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp := serve(t, m, crossSite); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross site logout with a rewritten method: %d", resp.StatusCode)
	}
}

func TestClientCertificateRequired(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)
	for name, uri := range map[string]string{
		"no certificate":            "",
		"machine certificate":       "spiffe://castelnuovo.eu/client/backup",
		"certificate without owner": "spiffe://castelnuovo.eu/yubikey/87654321",
		"owner is not a user ID":    "spiffe://castelnuovo.eu/yubikey/87654321/owner/luca",
		"another trust domain":      "spiffe://example.com/yubikey/87654321/owner/" + sub,
		"owner followed by a path":  cert + "/x",
		"user URI inside another":   "spiffe://example.com/" + cert,
	} {
		for path, method := range map[string]string{"/page": http.MethodGet, loginPath: http.MethodGet, callbackPath: http.MethodGet, logoutPath: http.MethodPost} {
			if resp := serve(t, m, httpRequest(method, path, uri, session)); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
				t.Fatalf("%s on %s: %d %v", name, path, resp.StatusCode, resp.Cookies())
			}
		}
	}

	unverified := httpRequest(http.MethodGet, "/page", cert, session)
	unverified.TLS = &tls.ConnectionState{PeerCertificates: unverified.TLS.VerifiedChains[0]}
	second := httpRequest(http.MethodGet, "/page", "spiffe://castelnuovo.eu/client/backup", session)
	second.TLS.VerifiedChains[0][0].URIs = append(second.TLS.VerifiedChains[0][0].URIs, must(url.Parse(cert)))
	for name, req := range map[string]*http.Request{"unverified certificate": unverified, "user URI after another URI": second} {
		if resp := serve(t, m, req); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
}

func TestSessionBinding(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)
	for name, tt := range map[string]struct{ host, uri string }{
		"another YubiKey of the same user": {host, otherKey},
		"certificate of another user":      {host, otherCert},
		"another host":                     {"other.castelnuovo.eu", cert},
	} {
		req := httpRequest(http.MethodGet, "/page", tt.uri, session)
		req.Host = tt.host
		if resp := serve(t, m, req); resp.StatusCode != http.StatusFound || resp.Header.Get("X-Auth-Sub") != "" {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("own host and certificate: %d", resp.StatusCode)
	}
}

func TestWithoutCertificate(t *testing.T) {
	m, idp := newTest(t)
	m.DisableClientCertificate = true
	session := logIn(t, m, idp, "")
	if resp := get(t, m, "/page", otherCert, session); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Auth-Sub") != sub {
		t.Fatalf("certificate is ignored: %d", resp.StatusCode)
	}

	strict := newAuth(t, idp, "secret")
	if resp := get(t, strict, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("site that requires a certificate: %d", resp.StatusCode)
	}
}

func TestLogs(t *testing.T) {
	m, idp := newTest(t)
	core, logs := observer.New(zap.InfoLevel)
	m.log = zap.New(core)

	session := logIn(t, m, idp, cert)
	get(t, m, "/page", otherKey, session)
	serve(t, m, httpRequest(http.MethodPost, logoutPath, cert, session))
	for _, message := range []string{"user logged in", "session used from another host or certificate", "user logged out"} {
		entries := logs.FilterMessage(message).All()
		if len(entries) != 1 || entries[0].ContextMap()["client_ip"] != clientIP || entries[0].ContextMap()["sub"] != sub || entries[0].ContextMap()["host"] != host {
			t.Fatalf("%q: %v", message, entries)
		}
	}

	resp := get(t, m, loginPath, cert)
	state := must(url.Parse(resp.Header.Get("Location"))).Query().Get("state")
	get(t, m, callbackPath+"?error=%3Cscript%3E&state="+state, cert, pending(resp))
	denied := logs.FilterMessage("request denied").All()
	if len(denied) != 1 || denied[0].ContextMap()["idp_error"] != "<script>" || strings.Contains(fmt.Sprint(denied[0].ContextMap()["error"]), "script") {
		t.Fatalf("request denied: %v", denied)
	}
}
