package castelnuovo

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	sessionLifetime = 12 * time.Hour
	refreshInterval = 5 * time.Minute
	retryInterval   = 10 * time.Second
	maxOutage       = 10 * time.Minute
)

type session struct {
	mu             sync.Mutex
	host, uri, sub string
	claims         *claims
	refreshToken   string
	refreshedAt    time.Time
	failedAt       time.Time
	failingSince   time.Time
	expiresAt      time.Time
}

type store struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newStore() *store {
	return &store{sessions: map[string]*session{}}
}

func (*store) Destruct() error { return nil }

func (s *store) get(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

func (s *store) add(sess *session, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.sessions {
		if !now.Before(existing.expiresAt) {
			delete(s.sessions, id)
		}
	}
	id := rand.Text()
	s.sessions[id] = sess
	return id
}

func (s *store) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// startSession stores a new session for c and gives the browser its cookie.
func (m *Auth) startSession(req *request, c *claims, refreshToken string) {
	now := m.now()
	id := m.store.add(&session{
		host:         req.r.Host,
		uri:          req.uri,
		sub:          c.Subject,
		claims:       c,
		refreshToken: refreshToken,
		refreshedAt:  now,
		expiresAt:    now.Add(sessionLifetime),
	}, now)
	setCookie(req.w, sessionCookie, id, sessionLifetime)
	req.log.Info("user logged in", zap.String("sub", c.Subject))
}

// endSession removes the request's session and its cookie, and returns its ID token.
func (m *Auth) endSession(req *request) string {
	setCookie(req.w, sessionCookie, "", -time.Second)
	sess := m.store.get(req.sessionID)
	if sess == nil {
		return ""
	}
	m.store.remove(req.sessionID)
	req.log.Info("user logged out", zap.String("sub", sess.sub))

	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.claims.idToken
}

// verify returns the claims of the request's session, or nil when it has no usable session.
func (m *Auth) verify(req *request) (*claims, error) {
	sess := m.findSession(req)
	if sess == nil {
		return nil, nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if m.store.get(req.sessionID) != sess {
		return nil, nil // the session ended while this request waited for the lock
	}
	err := m.refresh(context.WithoutCancel(req.r.Context()), sess)
	switch {
	case errors.Is(err, errUnavailable):
		return nil, deny(http.StatusBadGateway, err, zap.String("sub", sess.sub))
	case err != nil:
		m.store.remove(req.sessionID)
		req.log.Warn("session ended", zap.String("sub", sess.sub), zap.Error(err))
		return nil, nil
	}
	return sess.claims, nil
}

// findSession returns the request's session if it has not expired and was started on this
// host with this client certificate.
func (m *Auth) findSession(req *request) *session {
	sess := m.store.get(req.sessionID)
	switch {
	case sess == nil || !m.now().Before(sess.expiresAt):
		return nil
	case sess.host != req.r.Host || sess.uri != req.uri:
		req.log.Warn("session used from another host or certificate", zap.String("sub", sess.sub), zap.String("session_host", sess.host), zap.String("session_certificate", sess.uri))
		return nil
	}
	return sess
}

// refresh renews the tokens of sess once they are refreshInterval old. The caller holds sess.mu.
func (m *Auth) refresh(ctx context.Context, sess *session) error {
	now := m.now()
	switch {
	case now.Sub(sess.refreshedAt) < refreshInterval:
		return nil
	case now.Sub(sess.failedAt) < retryInterval:
		return errUnavailable
	}

	c, refreshToken, err := m.idp.refresh(ctx, sess.refreshToken)
	switch {
	case errors.Is(err, errUnavailable):
		return sess.unavailable(now, err)
	case err != nil:
		return err
	case c.Subject != sess.sub:
		return errors.New("refresh returned another user")
	}
	sess.claims, sess.refreshToken, sess.refreshedAt, sess.failingSince = c, refreshToken, now, time.Time{}
	return nil
}

// unavailable records a refresh that failed because the identity provider could not be
// reached. It keeps the session until refreshes have failed for maxOutage.
func (s *session) unavailable(now time.Time, err error) error {
	if s.failingSince.IsZero() {
		s.failingSince = now
	}
	if now.Sub(s.failingSince) >= maxOutage {
		return fmt.Errorf("refresh kept failing for %s: %v", maxOutage, err)
	}
	s.failedAt = now
	return err
}
