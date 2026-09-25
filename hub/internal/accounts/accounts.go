// Package accounts binds stored users to live forge credentials.
//
// Tokens are sealed at rest and only unsealed for the duration of a call. An
// expiring token is refreshed transparently and written back, so a monitored
// repository keeps working long after the user closed the browser.
package accounts

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gvinsot/SwiftProof/hub/internal/forge"
	"github.com/gvinsot/SwiftProof/hub/internal/secrets"
	"github.com/gvinsot/SwiftProof/hub/internal/store"
)

// Manager resolves providers and credentials for stored accounts.
type Manager struct {
	store     *store.Store
	keys      *secrets.Keyring
	providers map[string]forge.Provider
	mu        sync.Mutex
}

// New builds a manager over the configured providers.
func New(s *store.Store, keys *secrets.Keyring, providers map[string]forge.Provider) *Manager {
	return &Manager{store: s, keys: keys, providers: providers}
}

// Provider returns the forge implementation of a kind.
func (m *Manager) Provider(kind string) (forge.Provider, error) {
	p, ok := m.providers[kind]
	if !ok {
		return nil, fmt.Errorf("forge %q is not configured", kind)
	}
	return p, nil
}

// Providers lists the configured forge kinds.
func (m *Manager) Providers() map[string]forge.Provider { return m.providers }

// Save seals a freshly issued token onto a user record.
func (m *Manager) Save(u *store.User, t forge.Token) error {
	access, err := m.keys.Seal(t.AccessToken)
	if err != nil {
		return err
	}
	refresh := ""
	if t.RefreshToken != "" {
		if refresh, err = m.keys.Seal(t.RefreshToken); err != nil {
			return err
		}
	}
	u.Token, u.RefreshToken, u.TokenExpiry = access, refresh, t.Expiry
	return m.store.PutUser(u)
}

// Token unseals the credential of a user, refreshing it when it is about to
// expire. The refresh is serialized so concurrent analyses cannot race into
// two refreshes and invalidate each other's token.
func (m *Manager) Token(ctx context.Context, u *store.User) (forge.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	access, err := m.keys.Open(u.Token)
	if err != nil {
		return forge.Token{}, fmt.Errorf("stored credential of %s is unreadable: %w", u.Login, err)
	}
	refresh, err := m.keys.Open(u.RefreshToken)
	if err != nil {
		return forge.Token{}, fmt.Errorf("stored credential of %s is unreadable: %w", u.Login, err)
	}
	token := forge.Token{AccessToken: access, RefreshToken: refresh, Expiry: u.TokenExpiry}
	if !token.Expired(time.Now()) {
		return token, nil
	}
	p, err := m.Provider(u.Provider)
	if err != nil {
		return forge.Token{}, err
	}
	// Re-read the user: another worker may have refreshed it meanwhile.
	if latest, err := m.store.User(u.Key); err == nil && latest.TokenExpiry.After(u.TokenExpiry) {
		access, aerr := m.keys.Open(latest.Token)
		refreshed, rerr := m.keys.Open(latest.RefreshToken)
		if aerr == nil && rerr == nil {
			*u = *latest
			return forge.Token{AccessToken: access, RefreshToken: refreshed, Expiry: latest.TokenExpiry}, nil
		}
	}
	renewed, err := p.Refresh(ctx, token)
	if err != nil {
		return forge.Token{}, fmt.Errorf("the %s session of %s expired, sign in again: %w", u.Provider, u.Login, err)
	}
	if err := m.Save(u, renewed); err != nil {
		return forge.Token{}, err
	}
	return renewed, nil
}
