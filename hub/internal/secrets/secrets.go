// Package secrets seals data the hub must keep: forge access tokens at rest
// and the session cookie in the browser.
//
// One 32-byte deployment key is expanded into purpose-specific subkeys, so a
// value sealed for storage can never be replayed as a session cookie.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalid is returned for any value that fails authentication. Callers must
// not distinguish tampering from expiry in what they send back to a client.
var ErrInvalid = errors.New("invalid or expired value")

// Keyring derives the subkeys used by the hub.
type Keyring struct {
	storage []byte
	session []byte
	csrf    []byte
}

// New expands a 32-byte deployment key.
func New(key []byte) (*Keyring, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("deployment key must be 32 bytes, got %d", len(key))
	}
	return &Keyring{
		storage: derive(key, "swiftproof-hub/storage/v1"),
		session: derive(key, "swiftproof-hub/session/v1"),
		csrf:    derive(key, "swiftproof-hub/csrf/v1"),
	}, nil
}

func derive(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// Seal encrypts a value for storage on disk.
func (k *Keyring) Seal(plaintext string) (string, error) {
	gcm, err := aead(k.storage)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value produced by Seal.
func (k *Keyring) Open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	gcm, err := aead(k.storage)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < gcm.NonceSize() {
		return "", ErrInvalid
	}
	plaintext, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", ErrInvalid
	}
	return string(plaintext), nil
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Session is the authenticated identity carried by the cookie. It holds no
// forge credential: the sealed token stays server-side, keyed by UserKey.
type Session struct {
	UserKey  string `json:"u"`
	Provider string `json:"p"`
	Login    string `json:"l"`
	IssuedAt int64  `json:"i"`
	Expires  int64  `json:"e"`
	// Nonce makes the CSRF token session-specific and unpredictable.
	Nonce string `json:"n"`
}

// NewSession issues a session valid for ttl.
func NewSession(userKey, provider, login string, ttl time.Duration, now time.Time) (Session, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Session{}, err
	}
	return Session{
		UserKey:  userKey,
		Provider: provider,
		Login:    login,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce),
	}, nil
}

// SignSession encodes and authenticates a session for a cookie value.
func (k *Keyring) SignSession(s Session) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + sign(k.session, body), nil
}

// ReadSession authenticates a cookie value and rejects expired sessions.
func (k *Keyring) ReadSession(value string, now time.Time) (Session, error) {
	body, mac, found := strings.Cut(value, ".")
	if !found {
		return Session{}, ErrInvalid
	}
	if !hmac.Equal([]byte(mac), []byte(sign(k.session, body))) {
		return Session{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, ErrInvalid
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return Session{}, ErrInvalid
	}
	if s.UserKey == "" || s.Expires <= now.Unix() {
		return Session{}, ErrInvalid
	}
	return s, nil
}

// CSRF derives the double-submit token of a session. It is bound to the
// session nonce, so it cannot be reused across sessions or guessed.
func (k *Keyring) CSRF(s Session) string {
	return sign(k.csrf, s.UserKey+"|"+s.Nonce)
}

// CheckCSRF compares a submitted token in constant time.
func (k *Keyring) CheckCSRF(s Session, token string) bool {
	return token != "" && hmac.Equal([]byte(token), []byte(k.CSRF(s)))
}

// SignState authenticates the OAuth state parameter together with the forge
// it was issued for and the post-login destination.
func (k *Keyring) SignState(kind, redirect string, now time.Time) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"k": kind,
		"r": redirect,
		"e": now.Add(10 * time.Minute).Unix(),
		"n": base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + sign(k.session, body), nil
}

// ReadState authenticates an OAuth state parameter and returns the forge kind
// and the redirect target it was issued with.
func (k *Keyring) ReadState(value string, now time.Time) (kind, redirect string, err error) {
	body, mac, found := strings.Cut(value, ".")
	if !found || !hmac.Equal([]byte(mac), []byte(sign(k.session, body))) {
		return "", "", ErrInvalid
	}
	payload, decodeErr := base64.RawURLEncoding.DecodeString(body)
	if decodeErr != nil {
		return "", "", ErrInvalid
	}
	var state struct {
		Kind     string `json:"k"`
		Redirect string `json:"r"`
		Expires  int64  `json:"e"`
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return "", "", ErrInvalid
	}
	if state.Kind == "" || state.Expires <= now.Unix() {
		return "", "", ErrInvalid
	}
	return state.Kind, state.Redirect, nil
}

func sign(key []byte, body string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Random returns an unguessable URL-safe identifier of n bytes of entropy,
// used for webhook routing keys and webhook secrets.
func Random(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
