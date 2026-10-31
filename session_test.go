package castelnuovo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"
)

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

func TestSessionBinding(t *testing.T) {
	s, _ := newTest()
	session := cookie(logIn(t, s, cert), sessionCookie)

	if resp := get(s, "/page", otherCert, session); resp.StatusCode != http.StatusFound {
		t.Fatalf("another certificate: %d", resp.StatusCode)
	}
	if resp := get(s, "/page", cert, &http.Cookie{Name: sessionCookie, Value: "forged"}); resp.StatusCode != http.StatusFound {
		t.Fatalf("forged cookie: %d", resp.StatusCode)
	}
	req := httpRequest(http.MethodGet, "/page", cert, session)
	req.Host = "other.castelnuovo.eu"
	if resp := serve(s, req); resp.StatusCode != http.StatusFound {
		t.Fatalf("another host: %d", resp.StatusCode)
	}
	if resp := get(s, "/page", cert, session); resp.StatusCode != http.StatusOK {
		t.Fatalf("own host and certificate: %d", resp.StatusCode)
	}
}
