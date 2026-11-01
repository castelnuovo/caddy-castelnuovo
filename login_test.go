package castelnuovo

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
}

func TestLogoutEndsLoginAtIdentityProvider(t *testing.T) {
	m, idp := newTest(t)
	session := logIn(t, m, idp, cert)
	idp.endSession(serve(t, m, httpRequest(http.MethodPost, logoutPath, cert, session)).Header.Get("Location"))

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
