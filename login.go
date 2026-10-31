package castelnuovo

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	maxAuthAge       = time.Hour
	loginTimeout     = 10 * time.Minute
	maxPendingLogins = 3
)

var (
	crossOrigin    = http.NewCrossOriginProtection()
	errLoginTooOld = errors.New("login is too old")
)

type pendingLogin struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Redirect string `json:"redirect"`
	Reauth   bool   `json:"reauth,omitempty"`
}

func (m *Auth) login(req *request, redirect string, reauth bool) {
	dropPendingLogins(req)
	l := pendingLogin{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Redirect: redirect,
		Reauth:   reauth,
	}
	setCookie(req.w, loginCookie+l.State, l.cookie(), loginTimeout)
	http.Redirect(req.w, req.r, m.idp.authURL(callbackURL(req.r.Host), l.State, l.Nonce, l.Verifier, reauth), http.StatusFound)
}

func dropPendingLogins(req *request) {
	if len(req.logins) < maxPendingLogins {
		return
	}
	for state := range req.logins {
		setCookie(req.w, loginCookie+state, "", -time.Second)
	}
}

func (m *Auth) callback(req *request) error {
	query := original(req.r).Query()
	state := query.Get("state")
	if _, ok := req.logins[state]; !ok || state == "" {
		return m.callbackWithoutLogin(req)
	}
	l, err := takeLogin(req, state)
	if err != nil {
		return err
	}
	if query.Get("code") == "" {
		return deny(http.StatusForbidden, errors.New("identity provider returned an error"), zap.String("idp_error", query.Get("error")))
	}

	c, refreshToken, err := m.idp.exchange(req.r.Context(), callbackURL(req.r.Host), query.Get("code"), l.Verifier)
	switch {
	case errors.Is(err, errUnavailable):
		return deny(http.StatusBadGateway, err)
	case err != nil:
		return deny(http.StatusForbidden, err)
	}

	err = m.checkLogin(c, l.Nonce, req.uri)
	switch {
	case errors.Is(err, errLoginTooOld) && !l.Reauth:
		req.log.Info("asking for a new login", zap.String("sub", c.Subject), zap.Error(err))
		m.login(req, l.Redirect, true)
		return nil
	case err != nil:
		return deny(http.StatusForbidden, err, zap.String("sub", c.Subject))
	}

	m.startSession(req, c, refreshToken)
	redirectLocal(req, l.Redirect)
	return nil
}

func (m *Auth) callbackWithoutLogin(req *request) error {
	c, err := m.verify(req)
	switch {
	case err != nil:
		return err
	case c != nil:
		redirectLocal(req, "/")
		return nil
	}
	return deny(http.StatusBadRequest, errors.New("login cookie is missing"))
}

func takeLogin(req *request, state string) (pendingLogin, error) {
	value := req.logins[state]
	delete(req.logins, state)
	setCookie(req.w, loginCookie+state, "", -time.Second)

	l, err := decodeLogin(value)
	if err != nil || l.State != state {
		return pendingLogin{}, deny(http.StatusBadRequest, errors.New("login cookie is invalid"))
	}
	return l, nil
}

func (m *Auth) checkLogin(c *claims, nonce, uri string) error {
	switch {
	case c.Subject == "":
		return errors.New("ID token has no subject")
	case c.Nonce != nonce:
		return errors.New("ID token nonce does not match")
	case uri != "" && certificateOwner(uri) != c.Subject:
		return errors.New("client certificate belongs to another user")
	case !slices.Contains(c.AMR, "phr"):
		return errors.New("login did not use a passkey")
	case m.now().Sub(time.Unix(c.AuthTime, 0)) > maxAuthAge:
		return errLoginTooOld
	}
	return nil
}

func (m *Auth) logout(req *request) error {
	if err := crossOrigin.Check(req.r); err != nil {
		return deny(http.StatusForbidden, err)
	}
	idToken := m.endSession(req)
	http.Redirect(req.w, req.r, m.idp.logoutURL(idToken, "https://"+req.r.Host+"/"), http.StatusSeeOther)
	return nil
}

func (l pendingLogin) cookie() string {
	value := l.encode()
	if len(loginCookie)+len(l.State)+len(value) > maxCookieSize {
		l.Redirect = ""
		value = l.encode()
	}
	return value
}

func (l pendingLogin) encode() string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(l)
	return base64.RawURLEncoding.EncodeToString(b.Bytes())
}

func decodeLogin(value string) (pendingLogin, error) {
	var l pendingLogin
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		err = json.Unmarshal(data, &l)
	}
	return l, err
}

func redirectLocal(req *request, p string) {
	if !isLocalPath(p) {
		p = "/"
	}
	http.Redirect(req.w, req.r, p, http.StatusFound)
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.Contains(p, `\`) && !strings.ContainsFunc(p, unicode.IsControl)
}

func callbackURL(host string) string {
	return "https://" + host + callbackPath
}
