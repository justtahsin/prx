// Package users stores the pre-shared keys the server accepts.
//
// The store is a plain JSON file so an operator can inspect, back up or
// hand-edit it. It is reloaded automatically when it changes on disk, which
// is what lets `prxd user add` take effect without restarting the daemon.
package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/justtahsin/prx/internal/protocol"
)

// Errors returned by the store.
var (
	ErrNotFound = errors.New("prx: no such user")
	ErrExists   = errors.New("prx: user already exists")
	ErrBadKey   = errors.New("prx: malformed key")
)

// User is one credential entry.
type User struct {
	Name    string    `json:"name"`
	Key     string    `json:"key"` // base64url, no padding, 32 bytes decoded
	Created time.Time `json:"created"`
	Enabled bool      `json:"enabled"`
	Note    string    `json:"note,omitempty"`
}

// KeyBytes decodes the user's pre-shared key.
func (u User) KeyBytes() ([]byte, error) {
	return DecodeKey(u.Key)
}

// NewKey generates a fresh random pre-shared key in wire form.
func NewKey() (string, error) {
	key := make([]byte, protocol.KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return EncodeKey(key), nil
}

// EncodeKey renders a raw key for storage and for connection URLs.
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey parses a key from storage or a connection URL.
func DecodeKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if len(key) != protocol.KeySize {
		return nil, protocol.ErrKeySize
	}
	return key, nil
}

// Store is a concurrent view of the users file.
type Store struct {
	path string

	mu      sync.RWMutex
	users   []User
	keys    [][]byte // decoded keys, positionally matching users
	modTime time.Time
	size    int64
}

// Open loads the users file, creating an empty one if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.save(nil); err != nil {
			return nil, err
		}
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Path reports where the store is persisted.
func (s *Store) Path() string { return s.path }

func (s *Store) load() error {
	info, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	var users []User
	if len(data) > 0 {
		if err := json.Unmarshal(data, &users); err != nil {
			return fmt.Errorf("prx: parsing %s: %w", s.path, err)
		}
	}

	// Decode every key once, at load time, so the hot authentication path
	// never touches base64.
	keys := make([][]byte, len(users))
	for i, u := range users {
		key, err := u.KeyBytes()
		if err != nil {
			return fmt.Errorf("prx: user %q: %w", u.Name, err)
		}
		keys[i] = key
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.users, s.keys = users, keys
	s.modTime, s.size = info.ModTime(), info.Size()
	return nil
}

func (s *Store) save(users []User) error {
	if users == nil {
		users = []User{}
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	// Write to a sibling temporary file and rename, so a crash mid-write can
	// never leave the server with a truncated credential list.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".users-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Reload re-reads the file if it changed since the last read. The server
// calls this periodically so credential changes apply without a restart.
func (s *Store) Reload() error {
	info, err := os.Stat(s.path)
	if err != nil {
		return err
	}

	s.mu.RLock()
	unchanged := info.ModTime().Equal(s.modTime) && info.Size() == s.size
	s.mu.RUnlock()
	if unchanged {
		return nil
	}
	return s.load()
}

// Watch reloads the store on an interval until ctx-like stop channel closes.
func (s *Store) Watch(stop <-chan struct{}, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := s.Reload(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// Match finds the enabled user whose key produces clientTag for this
// connection's binding and nonce.
//
// Because no identifier travels on the wire, this is a linear scan: one
// HMAC-SHA256 over ~64 bytes per user, roughly 200ns each. Even a five
// figure user count stays under a couple of milliseconds per new connection,
// and it is the price of a handshake that carries nothing an observer could
// use to track or enumerate accounts.
func (s *Store) Match(binding, nonce, clientTag []byte) (User, []byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i, u := range s.users {
		if !u.Enabled {
			continue
		}
		want := protocol.ClientTag(s.keys[i], binding, nonce)
		if subtle.ConstantTimeCompare(want, clientTag) == 1 {
			return u, s.keys[i], true
		}
	}
	return User{}, nil, false
}

// List returns a copy of the current users.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, len(s.users))
	copy(out, s.users)
	return out
}

// Get returns one user by name.
func (s *Store) Get(name string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Name == name {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// Count reports how many users are enabled.
func (s *Store) Count() (total, enabled int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		total++
		if u.Enabled {
			enabled++
		}
	}
	return total, enabled
}

// Add creates a user with a freshly generated key.
func (s *Store) Add(name, note string) (User, error) {
	if name == "" {
		return User{}, errors.New("prx: user name must not be empty")
	}
	if _, err := s.Get(name); err == nil {
		return User{}, ErrExists
	}

	key, err := NewKey()
	if err != nil {
		return User{}, err
	}
	u := User{
		Name:    name,
		Key:     key,
		Created: time.Now().UTC().Truncate(time.Second),
		Enabled: true,
		Note:    note,
	}

	users := append(s.List(), u)
	if err := s.save(users); err != nil {
		return User{}, err
	}
	return u, s.load()
}

// Remove deletes a user.
func (s *Store) Remove(name string) error {
	users := s.List()
	out := users[:0]
	found := false
	for _, u := range users {
		if u.Name == name {
			found = true
			continue
		}
		out = append(out, u)
	}
	if !found {
		return ErrNotFound
	}
	if err := s.save(out); err != nil {
		return err
	}
	return s.load()
}

// SetEnabled turns a user's access on or off without discarding their key.
func (s *Store) SetEnabled(name string, enabled bool) error {
	users := s.List()
	found := false
	for i := range users {
		if users[i].Name == name {
			users[i].Enabled = enabled
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if err := s.save(users); err != nil {
		return err
	}
	return s.load()
}

// Rotate replaces a user's key, invalidating every link previously issued
// to them.
func (s *Store) Rotate(name string) (User, error) {
	users := s.List()
	key, err := NewKey()
	if err != nil {
		return User{}, err
	}

	var updated User
	found := false
	for i := range users {
		if users[i].Name == name {
			users[i].Key = key
			updated = users[i]
			found = true
			break
		}
	}
	if !found {
		return User{}, ErrNotFound
	}
	if err := s.save(users); err != nil {
		return User{}, err
	}
	return updated, s.load()
}
