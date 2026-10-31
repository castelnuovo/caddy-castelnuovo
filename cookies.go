package castelnuovo

import (
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookie = "__Host-castelnuovo"
	loginCookie   = "__Host-castelnuovo-login-"
	maxCookieSize = 4096
)

func removeCookies(r *http.Request) (sessionID string, logins map[string]string) {
	logins = map[string]string{}
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookie:
				sessionID = value
			case strings.HasPrefix(name, loginCookie):
				logins[strings.TrimPrefix(name, loginCookie)] = value
			case part != "":
				kept = append(kept, part)
			}
		}
	}

	r.Header.Del("Cookie")
	if len(kept) > 0 {
		r.Header.Set("Cookie", strings.Join(kept, "; "))
	}
	return sessionID, logins
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
