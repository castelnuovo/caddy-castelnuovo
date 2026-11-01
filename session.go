package castelnuovo

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

const (
	sessionLifetime = 12 * time.Hour
	refreshInterval = 5 * time.Minute
)

type session struct {
	IDToken      string `json:"i"`
	RefreshToken string `json:"r"`
	RefreshedAt  int64  `json:"f"`
	ExpiresAt    int64  `json:"x"`
	Host         string `json:"h"`
	Certificate  string `json:"c,omitempty"`
}

type refreshed struct {
	cookie *http.Cookie
	claims claims
}

func (m *Auth) authenticate(req *request) (*claims, error) {
	var s session
	now := m.now().Unix()
	if m.open(sessionCookie, req.session, &s) != nil || now >= s.ExpiresAt {
		return nil, nil
	}
	c, err := parseClaims(s.IDToken)
	switch {
	case err != nil:
		return nil, nil
	case s.Host != req.r.Host || s.Certificate != req.cert:
		req.log.Warn("session used from another host or certificate", zap.String("sub", c.Subject), zap.String("session_host", s.Host), zap.String("session_certificate", s.Certificate))
		return nil, nil
	case now-s.RefreshedAt < int64(refreshInterval.Seconds()):
		return &c, nil
	}

	v, err, _ := m.refreshes.Do(s.RefreshToken, func() (any, error) {
		return m.refresh(context.WithoutCancel(req.r.Context()), s, c.Subject)
	})
	switch {
	case errors.Is(err, errUnavailable):
		return nil, req.deny(http.StatusBadGateway, err, zap.String("sub", c.Subject))
	case err != nil:
		expire(req.w, sessionCookie)
		req.log.Warn("session ended", zap.String("sub", c.Subject), zap.Error(err))
		return nil, nil
	}
	r := v.(refreshed)
	http.SetCookie(req.w, r.cookie)
	return &r.claims, nil
}

func (m *Auth) refresh(ctx context.Context, s session, sub string) (refreshed, error) {
	t, err := m.idp.refresh(ctx, s.RefreshToken)
	if err != nil {
		return refreshed{}, err
	}
	c, err := parseClaims(t.idToken)
	switch {
	case err != nil:
		return refreshed{}, err
	case c.Subject != sub:
		return refreshed{}, errors.New("refresh returned another user")
	}
	now := m.now().Unix()
	if now >= s.ExpiresAt {
		return refreshed{}, errors.New("session expired during the refresh")
	}
	s.IDToken, s.RefreshToken, s.RefreshedAt = t.idToken, t.refreshToken, now
	cookie, err := m.seal(sessionCookie, s, int(s.ExpiresAt-now))
	return refreshed{cookie, c}, err
}
