package secrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return k
}

func TestNewRejectsAShortKey(t *testing.T) {
	if _, err := New([]byte("too short")); err == nil {
		t.Fatal("expected an error for a key that is not 32 bytes")
	}
}

func TestSealRoundTrip(t *testing.T) {
	k := testKeyring(t)
	sealed, err := k.Seal("gho_secret-token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(sealed, "gho_") {
		t.Fatal("the sealed value must not contain the plaintext")
	}
	got, err := k.Open(sealed)
	if err != nil || got != "gho_secret-token" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := k.Open(sealed + "tampered"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a tampered ciphertext must not open, got %v", err)
	}
	if empty, err := k.Open(""); err != nil || empty != "" {
		t.Fatalf("an absent value opens to the empty string, got %q, %v", empty, err)
	}
}

func TestSealIsNotDeterministic(t *testing.T) {
	k := testKeyring(t)
	first, _ := k.Seal("same")
	second, _ := k.Seal("same")
	if first == second {
		t.Fatal("two seals of the same value must differ; the nonce must be random")
	}
}

func TestAnotherDeploymentKeyCannotOpenTheData(t *testing.T) {
	sealed, err := testKeyring(t).Seal("token")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	other, _ := New(bytes.Repeat([]byte{9}, 32))
	if _, err := other.Open(sealed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a different key must not open the value, got %v", err)
	}
}

func TestSessionRoundTripAndExpiry(t *testing.T) {
	k := testKeyring(t)
	now := time.Now()
	sess, err := NewSession("user-key", "github", "octocat", time.Hour, now)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	cookie, err := k.SignSession(sess)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	read, err := k.ReadSession(cookie, now)
	if err != nil || read.UserKey != "user-key" || read.Login != "octocat" {
		t.Fatalf("ReadSession = %+v, %v", read, err)
	}
	if _, err := k.ReadSession(cookie, now.Add(2*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired session must be refused, got %v", err)
	}
}

func TestSessionForgeryIsRefused(t *testing.T) {
	k := testKeyring(t)
	now := time.Now()
	sess, _ := NewSession("user-key", "github", "octocat", time.Hour, now)
	cookie, _ := k.SignSession(sess)
	body, mac, _ := strings.Cut(cookie, ".")

	for name, value := range map[string]string{
		"no separator":   body,
		"wrong mac":      body + "." + mac[:len(mac)-2] + "AA",
		"swapped body":   "eyJ1IjoiYXR0YWNrZXIifQ." + mac,
		"empty":          "",
		"garbage base64": "!!!." + mac,
	} {
		if _, err := k.ReadSession(value, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: expected ErrInvalid, got %v", name, err)
		}
	}
}

func TestCSRFIsBoundToTheSession(t *testing.T) {
	k := testKeyring(t)
	now := time.Now()
	first, _ := NewSession("user-a", "github", "a", time.Hour, now)
	second, _ := NewSession("user-b", "github", "b", time.Hour, now)

	if !k.CheckCSRF(first, k.CSRF(first)) {
		t.Fatal("a session must accept its own token")
	}
	if k.CheckCSRF(first, k.CSRF(second)) {
		t.Fatal("the token of another session must be refused")
	}
	if k.CheckCSRF(first, "") {
		t.Fatal("an empty token must be refused")
	}
	// Two sessions of the same user differ by their nonce.
	third, _ := NewSession("user-a", "github", "a", time.Hour, now)
	if k.CSRF(third) == k.CSRF(first) {
		t.Fatal("two sessions of one user must not share a CSRF token")
	}
}

func TestStateCarriesTheForgeAndRedirect(t *testing.T) {
	k := testKeyring(t)
	now := time.Now()
	state, err := k.SignState("gitlab", "/app.html#/repo/x", now)
	if err != nil {
		t.Fatalf("SignState: %v", err)
	}
	kind, redirect, err := k.ReadState(state, now)
	if err != nil || kind != "gitlab" || redirect != "/app.html#/repo/x" {
		t.Fatalf("ReadState = %q, %q, %v", kind, redirect, err)
	}
	if _, _, err := k.ReadState(state, now.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an expired state must be refused, got %v", err)
	}
	if _, _, err := k.ReadState("forged.value", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a forged state must be refused, got %v", err)
	}
}

func TestRandomIsUnguessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := Random(18)
		if err != nil {
			t.Fatalf("Random: %v", err)
		}
		if len(v) < 20 {
			t.Fatalf("Random(18) = %q, too short", v)
		}
		if seen[v] {
			t.Fatal("Random returned a duplicate")
		}
		seen[v] = true
	}
}
