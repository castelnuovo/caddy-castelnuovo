package castelnuovo

import (
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	maxAuthAge       = time.Hour
	loginTimeout     = 10 * time.Minute
	maxPendingLogins = 3
)

var crossOrigin = http.NewCrossOriginProtection()

type pendingLogin struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r,omitempty"`
}

func (m *Auth) login(req *request) error {
	if len(req.logins) >= maxPendingLogins {
		for state := range req.logins {
			expire(req.w, loginCookie+state)
		}
	}
	state := rand.Text()
	l := pendingLogin{Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(), Redirect: req.orig.URL.Query().Get("rd")}
	c, err := m.seal(loginCookie+state, l, int(loginTimeout.Seconds()))
	if errors.Is(err, errCookieTooLarge) {
		l.Redirect = ""
		c, err = m.seal(loginCookie+state, l, int(loginTimeout.Seconds()))
	}
	if err != nil {
		return err
	}
	http.SetCookie(req.w, c)
	http.Redirect(req.w, req.r, m.idp.authURL(callbackURL(req.r.Host), state, l.Nonce, l.Verifier), http.StatusFound)
	return nil
}

func (m *Auth) callback(req *request) error {
	query := req.orig.URL.Query()
	state := query.Get("state")
	value, ok := req.logins[state]
	if !ok {
		return req.deny(http.StatusBadRequest, errors.New("callback without a pending login"))
	}
	expire(req.w, loginCookie+state)
	var l pendingLogin
	if err := m.open(loginCookie+state, value, &l); err != nil {
		return req.deny(http.StatusBadRequest, errors.New("login cookie is invalid"))
	}
	if query.Get("code") == "" {
		return req.deny(http.StatusForbidden, errors.New("identity provider returned an error"), zap.String("idp_error", query.Get("error")))
	}

	t, err := m.idp.exchange(req.r.Context(), callbackURL(req.r.Host), query.Get("code"), l.Verifier)
	switch {
	case errors.Is(err, errUnavailable):
		return req.deny(http.StatusBadGateway, err)
	case err != nil:
		return req.deny(http.StatusForbidden, err)
	}
	c, err := parseClaims(t.idToken)
	if err == nil {
		err = m.checkLogin(c, l.Nonce, req.cert)
	}
	if err != nil {
		return req.deny(http.StatusForbidden, err, zap.String("sub", c.Subject))
	}

	now := m.now()
	cookie, err := m.seal(sessionCookie, session{
		IDToken:      t.idToken,
		RefreshToken: t.refreshToken,
		RefreshedAt:  now.Unix(),
		ExpiresAt:    now.Add(sessionLifetime).Unix(),
		Host:         req.r.Host,
		Certificate:  req.cert,
	}, int(sessionLifetime.Seconds()))
	if err != nil {
		req.log.Error("login failed", zap.String("sub", c.Subject), zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	http.SetCookie(req.w, cookie)
	req.log.Info("user logged in", zap.String("sub", c.Subject))

	if !isLocalPath(l.Redirect) {
		l.Redirect = "/"
	}
	http.Redirect(req.w, req.r, l.Redirect, http.StatusFound)
	return nil
}

func (m *Auth) checkLogin(c claims, nonce, cert string) error {
	switch {
	case c.Subject == "":
		return errors.New("ID token has no subject")
	case c.Nonce != nonce:
		return errors.New("ID token nonce does not match")
	case !m.DisableClientCertificate && certificateOwner(cert) != c.Subject:
		return errors.New("client certificate belongs to another user")
	case !slices.Contains(c.AMR, "phr"):
		return errors.New("login did not use a passkey")
	case m.now().Sub(time.Unix(c.AuthTime, 0)) > maxAuthAge:
		return errors.New("login is older than 1 hour")
	}
	return nil
}

func (m *Auth) logout(req *request) error {
	if err := crossOrigin.Check(req.orig); err != nil {
		return req.deny(http.StatusForbidden, err)
	}
	expire(req.w, sessionCookie)
	var s session
	if m.open(sessionCookie, req.session, &s) == nil {
		c, _ := parseClaims(s.IDToken)
		req.log.Info("user logged out", zap.String("sub", c.Subject))
	}
	http.Redirect(req.w, req.r, m.idp.logoutURL(s.IDToken, "https://"+req.r.Host+"/"), http.StatusSeeOther)
	return nil
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, `\`) && !strings.ContainsFunc(p, unicode.IsControl)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}
