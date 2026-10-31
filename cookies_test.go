package castelnuovo

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestRemoveCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Cookie", `prefs={"theme":"dark"}; __Host-castelnuovo=session-id; name=café; path=a\b`)
	r.Header.Add("Cookie", loginCookie+"STATE=pending; spaced=a b; __Host-castelnuovo-login=old")
	sessionID, logins := removeCookies(r)
	if sessionID != "session-id" || !maps.Equal(logins, map[string]string{"STATE": "pending"}) {
		t.Fatalf("session %q, logins %v", sessionID, logins)
	}
	if want := []string{`prefs={"theme":"dark"}; name=café; path=a\b; spaced=a b`}; !slices.Equal(r.Header.Values("Cookie"), want) {
		t.Fatalf("app receives %q", r.Header.Values("Cookie"))
	}

	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", sessionCookie+"=session-id")
	removeCookies(r)
	if r.Header.Values("Cookie") != nil {
		t.Fatalf("app receives %q", r.Header.Values("Cookie"))
	}
}

func TestSetCookie(t *testing.T) {
	for maxAge, want := range map[time.Duration]string{
		time.Hour:    "__Host-castelnuovo=value; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax",
		-time.Second: "__Host-castelnuovo=value; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
	} {
		rec := httptest.NewRecorder()
		setCookie(rec, sessionCookie, "value", maxAge)
		if got := rec.Header().Get("Set-Cookie"); got != want {
			t.Fatalf("Set-Cookie %q, want %q", got, want)
		}
	}
}
