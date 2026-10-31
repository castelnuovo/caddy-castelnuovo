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

// request holds what the handler knows about the request it is serving.
type request struct {
	w         http.ResponseWriter
	r         *http.Request
	uri       string            // URI of the client certificate, empty when certificates are off
	sessionID string            // value of the session cookie
	logins    map[string]string // login cookies by state
	log       *zap.Logger
}

// denial is an error that ServeHTTP logs before turning it into a Caddy error.
type denial struct {
	status int
	err    error
	fields []zap.Field
}

func deny(status int, err error, fields ...zap.Field) error {
	return &denial{status, err, fields}
}

func (d *denial) Error() string { return d.err.Error() }

func (m *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	removeAuthHeaders(r)
	req := m.newRequest(w, r)
	err := m.route(req, next)
	if d, ok := errors.AsType[*denial](err); ok {
		req.log.Warn("request denied", append(d.fields, zap.String("path", original(r).Path), zap.Error(d.err))...)
		return caddyhttp.Error(d.status, d.err)
	}
	return err
}

func (m *Auth) newRequest(w http.ResponseWriter, r *http.Request) *request {
	sessionID, logins := removeCookies(r)
	req := &request{w: w, r: r, sessionID: sessionID, logins: logins}
	if !m.DisableClientCertificate {
		req.uri = clientCertificate(r)
	}

	fields := []zap.Field{zap.String("host", r.Host)}
	if req.uri != "" {
		fields = append(fields, zap.String("certificate", req.uri))
	}
	if clientIP, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); clientIP != "" {
		fields = append(fields, zap.String("client_ip", clientIP))
	}
	req.log = m.log.With(fields...)
	return req
}

func (m *Auth) route(req *request, next caddyhttp.Handler) error {
	if err := m.checkCertificate(req.uri); err != nil {
		return err
	}

	switch path, method := original(req.r).Path, req.r.Method; {
	case path == loginPath && method == http.MethodGet:
		m.login(req, original(req.r).Query().Get("rd"), false)
		return nil
	case path == callbackPath && method == http.MethodGet:
		return m.callback(req)
	case path == logoutPath && method == http.MethodPost:
		return m.logout(req)
	case path == loginPath || path == callbackPath:
		return methodNotAllowed(req.w, path, http.MethodGet)
	case path == logoutPath:
		return methodNotAllowed(req.w, path, http.MethodPost)
	}

	c, err := m.verify(req)
	switch {
	case err != nil:
		return err
	case c == nil:
		return challenge(req)
	}
	setAuthHeaders(req.r, c)
	return next.ServeHTTP(req.w, req.r)
}

func (m *Auth) checkCertificate(uri string) error {
	switch {
	case m.DisableClientCertificate:
		return nil
	case uri == "":
		return deny(http.StatusForbidden, errors.New("a client certificate is required"))
	case certificateOwner(uri) == "":
		return deny(http.StatusForbidden, errors.New("client certificate is not allowed"))
	}
	return nil
}

func clientCertificate(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0][0].URIs) == 0 {
		return ""
	}
	return r.TLS.VerifiedChains[0][0].URIs[0].String()
}

// certificateOwner returns the user ID in a YubiKey certificate URI, or "" for any other URI.
func certificateOwner(uri string) string {
	if match := yubikeyURI.FindStringSubmatch(uri); match != nil {
		return match[1]
	}
	return ""
}

// challenge sends a page load without a session to the login. Other requests can't follow
// that redirect, so they get a 401.
func challenge(req *request) error {
	if !isPageLoad(req.r) {
		return caddyhttp.Error(http.StatusUnauthorized, errors.New("login required"))
	}
	http.Redirect(req.w, req.r, loginPath+"?rd="+url.QueryEscape(original(req.r).RequestURI()), http.StatusFound)
	return nil
}

func isPageLoad(r *http.Request) bool {
	mode := r.Header.Get("Sec-Fetch-Mode")
	return r.Method == http.MethodGet && (mode == "" || mode == "navigate")
}

func methodNotAllowed(w http.ResponseWriter, path, allow string) error {
	w.Header().Set("Allow", allow)
	return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("%s only accepts %s", path, allow))
}

// removeAuthHeaders removes every header that could pass for one of ours, including spellings
// with underscores that CGI and some app servers treat as dashes.
func removeAuthHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToUpper(strings.ReplaceAll(name, "_", "-")), "X-AUTH-") {
			delete(r.Header, name)
		}
	}
}

func setAuthHeaders(r *http.Request, c *claims) {
	r.Header.Set("X-Auth-Sub", c.Subject)
	r.Header.Set("X-Auth-User", c.PreferredUsername)
	r.Header.Set("X-Auth-Name", c.Name)
	r.Header.Set("X-Auth-Email", c.Email)
	r.Header.Set("X-Auth-Groups", strings.Join(c.Groups, ","))
}

// original returns the URL the client asked for, before Caddy rewrote it.
func original(r *http.Request) *url.URL {
	if orig, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok {
		return orig.URL
	}
	return r.URL
}
