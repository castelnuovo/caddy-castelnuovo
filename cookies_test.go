package castelnuovo

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
