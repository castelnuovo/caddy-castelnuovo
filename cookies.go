package castelnuovo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const (
	sessionCookie = "__Host-castelnuovo"
	loginCookie   = "__Host-castelnuovo-login-"
	maxCookieSize = 4096
)

var errCookieTooLarge = errors.New("cookie is larger than 4096 bytes")

func newAEAD(secret string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "castelnuovo_auth cookies", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (m *Auth) seal(name string, v any, maxAge int) (*http.Cookie, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	c := newCookie(name, base64.RawURLEncoding.EncodeToString(m.aead.Seal(nil, nil, plaintext, []byte(name))), maxAge)
	if len(c.String()) > maxCookieSize {
		return nil, errCookieTooLarge
	}
	return c, nil
}

func (m *Auth) open(name, value string, v any) error {
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	plaintext, err := m.aead.Open(nil, nil, ciphertext, []byte(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, v)
}

func expire(w http.ResponseWriter, name string) {
	http.SetCookie(w, newCookie(name, "", -1))
}

func newCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func takeCookies(r *http.Request) (session string, logins map[string]string) {
	logins = map[string]string{}
	var kept []string
	for _, line := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(line, ";") {
			part = strings.TrimSpace(part)
			name, value, _ := strings.Cut(part, "=")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			switch {
			case name == sessionCookie:
				session = value
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
	return session, logins
}
