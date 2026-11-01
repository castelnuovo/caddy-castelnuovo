package castelnuovo

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	loginPath    = "/.castelnuovo/login"
	callbackPath = "/.castelnuovo/callback"
	logoutPath   = "/.castelnuovo/logout"
)

var yubikeyURI = regexp.MustCompile(`^spiffe://castelnuovo\.eu/yubikey/[0-9]+/owner/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type request struct {
	w       http.ResponseWriter
	r       *http.Request
	orig    *http.Request
	cert    string
	session string
	logins  map[string]string
	log     *zap.Logger
}

func (m *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	removeAuthHeaders(r)
	req := m.newRequest(w, r)
	if !m.DisableClientCertificate && certificateOwner(req.cert) == "" {
		return req.deny(http.StatusForbidden, errors.New("a client certificate of a user is required"))
	}

	switch path, method := req.orig.URL.Path, req.orig.Method; {
	case path == loginPath && method == http.MethodGet:
		return m.login(req)
	case path == callbackPath && method == http.MethodGet:
		return m.callback(req)
	case path == logoutPath && method == http.MethodPost:
		return m.logout(req)
	case path == loginPath || path == callbackPath:
		return methodNotAllowed(w, path, http.MethodGet)
	case path == logoutPath:
		return methodNotAllowed(w, path, http.MethodPost)
	}

	c, err := m.authenticate(req)
	switch {
	case err != nil:
		return err
	case c == nil:
		return challenge(req)
	}
	r.Header.Set("X-Auth-Sub", c.Subject)
	r.Header.Set("X-Auth-User", c.PreferredUsername)
	r.Header.Set("X-Auth-Name", c.Name)
	r.Header.Set("X-Auth-Email", c.Email)
	r.Header.Set("X-Auth-Groups", strings.Join(c.Groups, ","))
	return next.ServeHTTP(w, r)
}

func (m *Auth) newRequest(w http.ResponseWriter, r *http.Request) *request {
	req := &request{w: w, r: r, orig: r}
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		req.orig = &orig
	}
	req.session, req.logins = takeCookies(r)
	if !m.DisableClientCertificate {
		req.cert = clientCertificate(r)
	}

	fields := []zap.Field{zap.String("host", r.Host)}
	if req.cert != "" {
		fields = append(fields, zap.String("certificate", req.cert))
	}
	if clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); clientIP != "" {
		fields = append(fields, zap.String("client_ip", clientIP))
	}
	req.log = m.log.WithLazy(fields...)
	return req
}

func (req *request) deny(status int, err error, fields ...zap.Field) error {
	req.log.Warn("request denied", append(fields, zap.String("path", req.orig.URL.Path), zap.Error(err))...)
	return caddyhttp.Error(status, err)
}

func clientCertificate(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0][0].URIs) == 0 {
		return ""
	}
	return r.TLS.VerifiedChains[0][0].URIs[0].String()
}

func certificateOwner(uri string) string {
	if match := yubikeyURI.FindStringSubmatch(uri); match != nil {
		return match[1]
	}
	return ""
}

func challenge(req *request) error {
	mode, dest := req.r.Header.Get("Sec-Fetch-Mode"), req.r.Header.Get("Sec-Fetch-Dest")
	if req.orig.Method != http.MethodGet || mode != "" && mode != "navigate" || dest != "" && dest != "document" {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(req.w, req.r, loginPath+"?rd="+url.QueryEscape(req.orig.URL.RequestURI()), http.StatusFound)
	return nil
}

func methodNotAllowed(w http.ResponseWriter, path, allow string) error {
	w.Header().Set("Allow", allow)
	return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts %s", path, allow))
}

func removeAuthHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(r.Header, name)
		}
	}
}
