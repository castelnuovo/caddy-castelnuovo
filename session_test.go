package castelnuovo

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

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
