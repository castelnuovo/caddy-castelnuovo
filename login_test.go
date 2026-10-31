package castelnuovo

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
