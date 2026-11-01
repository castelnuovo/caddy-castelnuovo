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
	"testing/synctest"
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

func TestRefresh(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)

	idp.advance(refreshInterval - time.Second)
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 || idp.refreshes != 0 {
		t.Fatalf("before the refresh is due: %d %v, %d refreshes", resp.StatusCode, resp.Cookies(), idp.refreshes)
	}

	idp.user.Groups = []string{"admins"}
	idp.advance(time.Second)
	resp := get(t, m, "/page", cert, session)
	refreshed := cookieNamed(resp, sessionCookie)
	if resp.StatusCode != http.StatusOK || idp.refreshes != 1 || refreshed == nil || refreshed.Value == session.Value || resp.Header.Get("X-Auth-Groups") != "admins" {
		t.Fatalf("refresh: %d %v, %d refreshes, groups %q", resp.StatusCode, resp.Cookies(), idp.refreshes, resp.Header.Get("X-Auth-Groups"))
	}
	if refreshed.MaxAge != int((sessionLifetime - refreshInterval).Seconds()) {
		t.Fatalf("refresh extended the session to %ds", refreshed.MaxAge)
	}
	if resp := get(t, m, "/page", cert, refreshed); resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 || idp.refreshes != 1 {
		t.Fatalf("refreshed cookie: %d, %d refreshes", resp.StatusCode, idp.refreshes)
	}
}

func TestSessionExpires(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)

	idp.advance(sessionLifetime - time.Second)
	resp := get(t, m, "/page", cert, session)
	refreshed := cookieNamed(resp, sessionCookie)
	if resp.StatusCode != http.StatusOK || refreshed == nil || refreshed.MaxAge != 1 {
		t.Fatalf("last second: %d %v", resp.StatusCode, resp.Cookies())
	}

	idp.advance(time.Second)
	if resp := get(t, m, "/page", cert, refreshed); resp.StatusCode != http.StatusFound || idp.refreshes != 1 {
		t.Fatalf("after 12 hours: %d, %d refreshes", resp.StatusCode, idp.refreshes)
	}

	m, idp = newTest(t)
	session = logIn(t, m, idp, cert)
	idp.advance(sessionLifetime - time.Second)
	idp.onRefresh = func() { idp.advance(time.Second) }
	resp = get(t, m, "/page", cert, session)
	if expired := cookieNamed(resp, sessionCookie); resp.StatusCode != http.StatusFound || expired == nil || expired.MaxAge >= 0 {
		t.Fatalf("refresh that ends after 12 hours: %d %v", resp.StatusCode, resp.Cookies())
	}
}

func TestRejectsInvalidSessionCookies(t *testing.T) {
	m, idp := newTest(t)
	valid := logIn(t, m, idp, cert)
	login := pending(get(t, m, loginPath, cert))
	other := newAuth(t, idp, "other secret")

	var s session
	if err := m.open(sessionCookie, valid.Value, &s); err != nil {
		t.Fatal(err)
	}
	s.ExpiresAt = idp.now().Unix()
	expired, err := m.seal(sessionCookie, s, 60)
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]string{
		"tampered":                tamper(valid.Value),
		"truncated":               valid.Value[:len(valid.Value)-1],
		"not base64":              "%%%",
		"too short":               "AAAA",
		"sealed with another key": logIn(t, other, idp, cert).Value,
		"login cookie":            login.Value,
		"expired payload":         expired.Value,
	} {
		if resp := get(t, m, "/page", cert, &http.Cookie{Name: sessionCookie, Value: value}); resp.StatusCode != http.StatusFound || resp.Header.Get("X-Auth-Sub") != "" {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	if idp.refreshes != 0 {
		t.Fatalf("%d refreshes", idp.refreshes)
	}
}

func TestSessionNeedsSignedIDToken(t *testing.T) {
	unsigned := func(f *fakePocketID, subject string) string {
		return fakeJWT(map[string]any{"iss": issuer, "aud": clientID, "sub": subject, "exp": f.now().Add(time.Hour).Unix(), "amr": []string{"phr"}, "groups": []string{"admins", "users", "root"}})
	}
	tests := map[string]struct {
		change func(*session, *fakePocketID)
		status int
	}{
		"unsigned ID token":                            {func(s *session, f *fakePocketID) { s.IDToken, s.RefreshToken = unsigned(f, sub), "forged" }, http.StatusFound},
		"unsigned ID token of another user":            {func(s *session, f *fakePocketID) { s.IDToken = unsigned(f, otherSub) }, http.StatusFound},
		"unsigned ID token while the provider is down": {func(s *session, f *fakePocketID) { s.IDToken, f.down = unsigned(f, sub), true }, http.StatusBadGateway},
		"expired ID token":                             {func(_ *session, f *fakePocketID) { f.advance(time.Hour) }, http.StatusOK},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, idp := newTest(t)
			var s session
			if err := m.open(sessionCookie, logIn(t, m, idp, cert).Value, &s); err != nil {
				t.Fatal(err)
			}
			tt.change(&s, idp)
			s.RefreshedAt = idp.now().Unix()
			forged, err := m.seal(sessionCookie, s, 60)
			if err != nil {
				t.Fatal(err)
			}

			resp := get(t, m, "/page", cert, forged)
			if resp.StatusCode != tt.status || idp.refreshes != 1 || resp.Header.Get("X-Auth-Groups") == "admins,users,root" {
				t.Fatalf("%d %q, %d refreshes", resp.StatusCode, resp.Header.Get("X-Auth-Groups"), idp.refreshes)
			}
			if tt.status == http.StatusOK && (resp.Header.Get("X-Auth-Sub") != sub || cookieNamed(resp, sessionCookie) == nil) {
				t.Fatalf("refreshed session: %q %v", resp.Header.Get("X-Auth-Sub"), resp.Cookies())
			}
		})
	}
}

func TestRefreshEndsSession(t *testing.T) {
	tests := map[string]func(*fakePocketID){
		"user disabled":        func(f *fakePocketID) { f.disabled = true },
		"another user":         func(f *fakePocketID) { f.user.Subject = otherSub },
		"groups no longer fit": func(f *fakePocketID) { f.user.Groups = groups(100) },
		"login revoked at the provider": func(f *fakePocketID) {
			for _, g := range f.hints {
				g.revoked = true
			}
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			m, idp := newTest(t)
			core, logs := observer.New(zap.InfoLevel)
			m.log = zap.New(core)
			session := logIn(t, m, idp, cert)
			change(idp)
			idp.advance(refreshInterval)

			resp := get(t, m, "/page", cert, session)
			expired := cookieNamed(resp, sessionCookie)
			if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != loginPath+"?rd=%2Fpage" || expired == nil || expired.MaxAge >= 0 {
				t.Fatalf("%d %v", resp.StatusCode, resp.Cookies())
			}
			if entries := logs.FilterMessage("session ended").All(); len(entries) != 1 || entries[0].ContextMap()["sub"] != sub {
				t.Fatalf("logs: %v", logs.All())
			}
		})
	}
}

func TestUnavailableIdentityProvider(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)
	idp.down = true

	idp.advance(refreshInterval - time.Second)
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("before the refresh is due: %d", resp.StatusCode)
	}
	idp.advance(time.Second)
	for i := range 2 {
		if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusBadGateway || len(resp.Cookies()) != 0 || resp.Header.Get("X-Auth-Sub") != "" || idp.refreshes != i+1 {
			t.Fatalf("refresh due: %d %v, %d refreshes", resp.StatusCode, resp.Cookies(), idp.refreshes)
		}
	}

	idp.down = false
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK || cookieNamed(resp, sessionCookie) == nil {
		t.Fatalf("after the outage: %d", resp.StatusCode)
	}
}

func TestConcurrentRefreshes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, idp := newTest(t)
		session := logIn(t, m, idp, cert)
		idp.advance(refreshInterval)
		release := make(chan struct{})
		idp.onRefresh = func() { <-release }

		responses := make([]*http.Response, 5)
		var wg sync.WaitGroup
		for i := range responses {
			wg.Go(func() { responses[i] = get(t, m, "/page", cert, session) })
		}
		synctest.Wait()
		close(release)
		wg.Wait()

		want := cookieNamed(responses[0], sessionCookie)
		for _, resp := range responses {
			if c := cookieNamed(resp, sessionCookie); resp.StatusCode != http.StatusOK || c == nil || c.Value != want.Value {
				t.Fatalf("%d %v", resp.StatusCode, resp.Cookies())
			}
		}
		if idp.refreshes != 1 {
			t.Fatalf("%d refreshes", idp.refreshes)
		}
	})
}

func TestCancelledRequestKeepsRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, idp := newTest(t)
		session := logIn(t, m, idp, cert)
		idp.advance(refreshInterval)
		release := make(chan struct{})
		idp.onRefresh = func() { <-release }

		first := httpRequest(http.MethodGet, "/page", cert, session)
		ctx, cancel := context.WithCancel(first.Context())
		var wg sync.WaitGroup
		var waiting *http.Response
		wg.Go(func() { serve(t, m, first.WithContext(ctx)) })
		synctest.Wait()
		wg.Go(func() { waiting = get(t, m, "/page", cert, session) })
		synctest.Wait()
		cancel()
		close(release)
		wg.Wait()

		if waiting.StatusCode != http.StatusOK || cookieNamed(waiting, sessionCookie) == nil || idp.refreshes != 1 {
			t.Fatalf("%d %v, %d refreshes", waiting.StatusCode, waiting.Cookies(), idp.refreshes)
		}
	})
}

func TestRefreshAcrossInstances(t *testing.T) {
	m, idp := newTest(t)
	other := newAuth(t, idp, "secret")
	session := logIn(t, m, idp, cert)
	idp.advance(refreshInterval)

	first := cookieNamed(get(t, m, "/page", cert, session), sessionCookie)
	if first == nil {
		t.Fatal("first refresh set no cookie")
	}
	idp.advance(30 * time.Second)
	if resp := get(t, other, "/page", cert, session); resp.StatusCode != http.StatusOK || cookieNamed(resp, sessionCookie) == nil {
		t.Fatalf("parallel refresh on another instance: %d", resp.StatusCode)
	}

	idp.advance(time.Minute)
	if resp := get(t, other, "/page", cert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("stale copy after the grace period: %d", resp.StatusCode)
	}
	idp.advance(refreshInterval)
	if resp := get(t, m, "/page", cert, first); resp.StatusCode != http.StatusFound {
		t.Fatalf("session after its grant was revoked: %d", resp.StatusCode)
	}
}

func TestSessionCookieSize(t *testing.T) {
	for _, n := range []int{0, 10, 30, 100} {
		m, idp := newTest(t)
		core, logs := observer.New(zap.InfoLevel)
		m.log = zap.New(core)
		idp.user.Groups = groups(n)
		resp := finishLogin(t, m, idp, get(t, m, loginPath, cert), cert)
		session := cookieNamed(resp, sessionCookie)
		if fits := n <= 30; fits != (session != nil) {
			t.Fatalf("%d groups: %d", n, resp.StatusCode)
		}
		if session == nil {
			if resp.StatusCode != http.StatusInternalServerError || logs.FilterMessage("login failed").Len() != 1 {
				t.Fatalf("%d groups: %d %v", n, resp.StatusCode, logs.All())
			}
			continue
		}
		t.Logf("%d groups: Set-Cookie of %d bytes, value of %d bytes", n, len(session.String()), len(session.Value))
	}
}

func groups(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("group-name-%05d", i)
	}
	return names
}

func TestLogin(t *testing.T) {
	m, idp := newTest(t)
	resp := get(t, m, loginPath+"?rd=%2Fpage", cert)
	login := pending(resp)
	location := must(url.Parse(resp.Header.Get("Location")))
	query := location.Query()
	if resp.StatusCode != http.StatusFound || location.Scheme+"://"+location.Host+location.Path != issuer+"/authorize" || login == nil || login.Name != loginCookie+query.Get("state") || login.MaxAge != 600 {
		t.Fatalf("login: %d %s %v", resp.StatusCode, location, resp.Cookies())
	}
	if query.Get("redirect_uri") != "https://"+host+callbackPath || query.Get("code_challenge_method") != "S256" || query.Get("max_age") != "3600" || query.Get("nonce") == "" || query.Has("prompt") {
		t.Fatalf("authorize URL %s", location)
	}

	resp = finishLogin(t, m, idp, resp, cert)
	session, expired := cookieNamed(resp, sessionCookie), cookieNamed(resp, login.Name)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/page" || session == nil || session.MaxAge != int(sessionLifetime.Seconds()) || expired == nil || expired.MaxAge >= 0 {
		t.Fatalf("callback: %d %s %v", resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
	}
}

func TestLoginRejects(t *testing.T) {
	tests := map[string]struct {
		uri    string
		change func(*fakePocketID)
	}{
		"nonce does not match":        {cert, func(f *fakePocketID) { f.user.Nonce = "other" }},
		"no subject":                  {cert, func(f *fakePocketID) { f.user.Subject = "" }},
		"no passkey":                  {cert, func(f *fakePocketID) { f.user.AMR = []string{"pwd"} }},
		"login older than an hour":    {cert, func(f *fakePocketID) { f.user.AuthTime = f.now().Add(-maxAuthAge - time.Second).Unix() }},
		"certificate of another user": {otherCert, func(*fakePocketID) {}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m, idp := newTest(t)
			tt.change(idp)
			resp := finishLogin(t, m, idp, get(t, m, loginPath, tt.uri), tt.uri)
			if resp.StatusCode != http.StatusForbidden || cookieNamed(resp, sessionCookie) != nil || pending(resp) != nil || resp.Header.Get("Location") != "" {
				t.Fatalf("%d %s %v", resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
			}
		})
	}
}

func TestLoginFailsAtIdentityProvider(t *testing.T) {
	m, idp := newTest(t)
	resp := get(t, m, loginPath, cert)
	state := must(url.Parse(resp.Header.Get("Location"))).Query().Get("state")
	if resp := get(t, m, callbackPath+"?error=access_denied&state="+state, cert, pending(resp)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("error from the identity provider: %d", resp.StatusCode)
	}

	idp.down = true
	if resp := finishLogin(t, m, idp, get(t, m, loginPath, cert), cert); resp.StatusCode != http.StatusBadGateway || cookieNamed(resp, sessionCookie) != nil {
		t.Fatalf("identity provider down: %d", resp.StatusCode)
	}
}

func TestLoginNeedsPKCE(t *testing.T) {
	m, idp := newTest(t)
	attacker := must(url.Parse(idp.authorize(get(t, m, loginPath, cert).Header.Get("Location")))).Query()
	victim := get(t, m, loginPath, cert)
	query := must(url.Parse(victim.Header.Get("Location"))).Query()
	idp.user.Nonce = query.Get("nonce")

	resp := get(t, m, callbackPath+"?"+url.Values{"code": {attacker.Get("code")}, "state": {query.Get("state")}}.Encode(), cert, pending(victim))
	if resp.StatusCode != http.StatusForbidden || cookieNamed(resp, sessionCookie) != nil {
		t.Fatalf("code of another login: %d", resp.StatusCode)
	}
}

func TestCallbackNeedsItsPendingLogin(t *testing.T) {
	m, idp := newTest(t)
	first, second := get(t, m, loginPath, cert), get(t, m, loginPath, cert)
	callback := idp.authorize(first.Header.Get("Location"))
	state := must(url.Parse(callback)).Query().Get("state")
	tampered := *pending(first)
	tampered.Value = tamper(tampered.Value)

	for name, cookies := range map[string][]*http.Cookie{
		"another browser":       nil,
		"another pending login": {pending(second)},
		"renamed login cookie":  {{Name: loginCookie + state, Value: pending(second).Value}},
		"tampered login cookie": {&tampered},
	} {
		if resp := get(t, m, callback, cert, cookies...); resp.StatusCode != http.StatusBadRequest || cookieNamed(resp, sessionCookie) != nil {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp := get(t, m, callbackPath+"?code=x", cert, pending(first)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("without state: %d", resp.StatusCode)
	}

	session := cookieNamed(get(t, m, callback, cert, pending(first)), sessionCookie)
	if resp := get(t, m, callback, cert, session); session == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback: %d", resp.StatusCode)
	}
}

func TestConcurrentLogins(t *testing.T) {
	m, idp := newTest(t)
	first, second := get(t, m, loginPath+"?rd=%2Ffirst", cert), get(t, m, loginPath+"?rd=%2Fsecond", cert)
	both := []*http.Cookie{pending(first), pending(second)}
	for login, want := range map[*http.Response]string{second: "/second", first: "/first"} {
		resp := get(t, m, idp.authorize(login.Header.Get("Location")), cert, both...)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want || cookieNamed(resp, sessionCookie) == nil {
			t.Fatalf("%s: %d %s", want, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestPendingLoginsAreLimited(t *testing.T) {
	m, _ := newTest(t)
	var logins []*http.Cookie
	for range maxPendingLogins {
		resp := get(t, m, loginPath, cert, logins...)
		if len(resp.Cookies()) != 1 {
			t.Fatalf("login %d set %v", len(logins)+1, resp.Cookies())
		}
		logins = append(logins, pending(resp))
	}

	resp := get(t, m, loginPath, cert, logins...)
	expired := 0
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			expired++
		}
	}
	if expired != maxPendingLogins || pending(resp) == nil {
		t.Fatalf("login after %d pending logins set %v", maxPendingLogins, resp.Cookies())
	}
}

func TestLongRedirect(t *testing.T) {
	m, idp := newTest(t)
	for rd, want := range map[string]string{
		"/" + strings.Repeat("a", 2000):  "/" + strings.Repeat("a", 2000),
		"/" + strings.Repeat("a&", 3000): "/",
	} {
		resp := finishLogin(t, m, idp, get(t, m, loginPath+"?rd="+url.QueryEscape(rd), cert), cert)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
			t.Fatalf("redirect of %d bytes: %d, location of %d bytes", len(rd), resp.StatusCode, len(resp.Header.Get("Location")))
		}
	}

	kept := 0
	for n := 2800; n < 3000; n++ {
		rd := "/" + strings.Repeat("a", n)
		switch resp := finishLogin(t, m, idp, get(t, m, loginPath+"?rd="+rd, cert), cert); resp.Header.Get("Location") {
		case rd:
			kept++
		case "/":
		default:
			t.Fatalf("redirect of %d bytes: %d", len(rd), resp.StatusCode)
		}
	}
	if kept == 0 || kept == 200 {
		t.Fatalf("kept %d of 200 redirects near the cookie limit", kept)
	}
}

func TestRedirectsOnlyToLocalPaths(t *testing.T) {
	m, idp := newTest(t)
	for rd, want := range map[string]string{
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
		resp := finishLogin(t, m, idp, get(t, m, loginPath+"?rd="+url.QueryEscape(rd), cert), cert)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
			t.Fatalf("rd %q: %d %q", rd, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestLogout(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)

	for name, header := range map[string][2]string{
		"cross site":        {"Sec-Fetch-Site", "cross-site"},
		"same site":         {"Sec-Fetch-Site", "same-site"},
		"another host":      {"Origin", "https://evil.example"},
		"another port":      {"Origin", "https://" + host + ":8443"},
		"another subdomain": {"Origin", "https://other.castelnuovo.eu"},
	} {
		req := httpRequest(http.MethodPost, logoutPath, cert, session)
		req.Header.Set(header[0], header[1])
		if resp := serve(t, m, req); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Fatalf("%s: %d %v", name, resp.StatusCode, resp.Cookies())
		}
	}

	var hint string
	for name, cookies := range map[string][]*http.Cookie{
		"with session":    {session},
		"without session": nil,
		"invalid session": {{Name: sessionCookie, Value: "invalid"}},
	} {
		req := httpRequest(http.MethodPost, logoutPath, cert, cookies...)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp := serve(t, m, req)
		location := must(url.Parse(resp.Header.Get("Location")))
		query, expired := location.Query(), cookieNamed(resp, sessionCookie)
		if resp.StatusCode != http.StatusSeeOther || location.Scheme+"://"+location.Host+location.Path != issuer+"/api/oidc/end-session" || query.Get("post_logout_redirect_uri") != "https://"+host+"/" || query.Get("client_id") != clientID || expired == nil || expired.MaxAge >= 0 {
			t.Fatalf("%s: %d %s %v", name, resp.StatusCode, location, resp.Cookies())
		}
		if (name == "with session") != query.Has("id_token_hint") {
			t.Fatalf("%s: hint %q", name, query.Get("id_token_hint"))
		}
		if name == "with session" {
			hint = query.Get("id_token_hint")
		}
	}
	if c, err := parseClaims(hint); err != nil || c.Subject != sub {
		t.Fatalf("hint is not the ID token: %v %+v", err, c)
	}
	if idp.endSessions != 1 {
		t.Fatalf("ended %d sessions at the identity provider", idp.endSessions)
	}
}

func TestLogoutEndsLoginAtIdentityProvider(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)
	if resp := serve(t, m, httpRequest(http.MethodPost, logoutPath, cert, session)); resp.StatusCode != http.StatusSeeOther || idp.endSessions != 1 {
		t.Fatalf("logout: %d, %d sessions ended", resp.StatusCode, idp.endSessions)
	}

	idp.advance(refreshInterval - time.Second)
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("copied cookie before its next refresh: %d", resp.StatusCode)
	}
	idp.advance(time.Second)
	resp := get(t, m, "/page", cert, session)
	if expired := cookieNamed(resp, sessionCookie); resp.StatusCode != http.StatusFound || expired == nil || expired.MaxAge >= 0 {
		t.Fatalf("copied cookie at its next refresh: %d %v", resp.StatusCode, resp.Cookies())
	}
}

func TestLogoutWhileIdentityProviderIsDown(t *testing.T) {
	m, idp := newTest(t)
	core, logs := observer.New(zap.InfoLevel)
	m.log = zap.New(core)
	session := logIn(t, m, idp, cert)

	idp.down = true
	resp := serve(t, m, httpRequest(http.MethodPost, logoutPath, cert, session))
	if expired := cookieNamed(resp, sessionCookie); resp.StatusCode != http.StatusSeeOther || expired == nil || expired.MaxAge >= 0 {
		t.Fatalf("logout: %d %v", resp.StatusCode, resp.Cookies())
	}
	if entries := logs.FilterMessage("logout did not end the login at the identity provider").All(); len(entries) != 1 || entries[0].ContextMap()["sub"] != sub {
		t.Fatalf("logs: %v", logs.All())
	}

	idp.down = false
	idp.advance(refreshInterval)
	if resp := get(t, m, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("copied cookie after the outage: %d", resp.StatusCode)
	}
}

func TestSealedCookie(t *testing.T) {
	m, idp := newTest(t)
	c, err := m.seal(sessionCookie, session{Host: host}, 60)
	if err != nil || c.Name != sessionCookie || c.MaxAge != 60 || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("%v %+v", err, c)
	}
	var s session
	if err := m.open(sessionCookie, c.Value, &s); err != nil || s.Host != host {
		t.Fatalf("%v %+v", err, s)
	}

	for name, open := range map[string]func() error{
		"tampered":     func() error { return m.open(sessionCookie, tamper(c.Value), &s) },
		"another name": func() error { return m.open(loginCookie+"STATE", c.Value, &s) },
		"another key":  func() error { return newAuth(t, idp, "other secret").open(sessionCookie, c.Value, &s) },
		"too short":    func() error { return m.open(sessionCookie, "AAAA", &s) },
		"empty":        func() error { return m.open(sessionCookie, "", &s) },
	} {
		if err := open(); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}

	if _, err := m.seal(sessionCookie, session{Host: strings.Repeat("a", maxCookieSize)}, 60); !errors.Is(err, errCookieTooLarge) {
		t.Fatalf("large cookie: %v", err)
	}
}

func TestExpire(t *testing.T) {
	rec := httptest.NewRecorder()
	expire(rec, sessionCookie)
	if got := rec.Header().Get("Set-Cookie"); got != "__Host-castelnuovo=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" {
		t.Fatalf("Set-Cookie %q", got)
	}
}

func TestTakeCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Cookie", "a=1; __Host-castelnuovo=old; "+loginCookie+"ONE=x")
	r.Header.Add("Cookie", " b = 2 ;__Host-castelnuovo=new;; __Host-castelnuovo-app=3; "+loginCookie+"TWO=y")
	session, logins := takeCookies(r)
	if session != "new" || len(logins) != 2 || logins["ONE"] != "x" || logins["TWO"] != "y" {
		t.Fatalf("%q %v", session, logins)
	}
	if got := r.Header.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b = 2; __Host-castelnuovo-app=3" {
		t.Fatalf("kept %q", got)
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", sessionCookie+"=only")
	if session, _ := takeCookies(r); session != "only" || r.Header.Values("Cookie") != nil {
		t.Fatalf("%q kept %q", session, r.Header.Values("Cookie"))
	}
}
