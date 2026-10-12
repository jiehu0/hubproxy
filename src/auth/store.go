package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("令牌无效或已过期")

// Only a digest is persisted. The original credential is returned once on creation.
type Token struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	DurationSeconds int64      `json:"duration_seconds"`
	CreatedAt       time.Time  `json:"created_at"`
	ActivatedAt     *time.Time `json:"activated_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

// Store is for one HubProxy process with a persistent, private data directory.
// Activation is serialized and committed before the first request is admitted.
type Store struct {
	mu     sync.Mutex
	path   string
	tokens map[string]Token
	now    func() time.Time
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// 128 random bits encoded as 26 lowercase characters, valid in Docker paths.
func randomProxySecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

func validProxySecret(secret string) bool {
	if len(secret) == 64 {
		_, err := hex.DecodeString(secret)
		return err == nil
	}
	if len(secret) != 26 {
		return false
	}
	for _, c := range secret {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, tokens: make(map[string]Token), now: time.Now}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(data, &s.tokens); err != nil || s.tokens == nil {
			return nil, fmt.Errorf("invalid token store: %s", path)
		}
		for id, t := range s.tokens {
			if id != t.ID || t.DurationSeconds < 60 || t.DurationSeconds > 2592000 || (t.ActivatedAt == nil) != (t.ExpiresAt == nil) {
				return nil, errors.New("invalid token record")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.save(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) save() error {
	data, err := json.Marshal(s.tokens)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), s.path)
}

func (s *Store) Create(name string, seconds int64) (string, Token, error) {
	if seconds < 60 || seconds > 2592000 {
		return "", Token{}, errors.New("有效时长应在 1 分钟至 30 天之间")
	}
	secret, err := randomProxySecret()
	if err != nil {
		return "", Token{}, err
	}
	t := Token{ID: digest(secret), Name: name, DurationSeconds: seconds, CreatedAt: s.now().UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) >= 10000 {
		return "", Token{}, errors.New("令牌数量已达上限，请删除过期令牌")
	}
	s.tokens[t.ID] = t
	if err := s.save(); err != nil {
		delete(s.tokens, t.ID)
		return "", Token{}, err
	}
	return secret, t, nil
}

// Authorize uses an absolute expiry; later requests never extend it.
func (s *Store) Authorize(secret string, activate bool) error {
	if !validProxySecret(secret) {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := digest(secret)
	t, ok := s.tokens[id]
	now := s.now().UTC()
	if !ok || (t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)) {
		return ErrDenied
	}
	if t.ActivatedAt == nil && activate {
		old := t
		expires := now.Add(time.Duration(t.DurationSeconds) * time.Second)
		t.ActivatedAt, t.ExpiresAt = &now, &expires
		s.tokens[id] = t
		if err := s.save(); err != nil {
			s.tokens[id] = old
			return err
		}
	}
	return nil
}

func (s *Store) List() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.tokens[id]
	if !ok {
		return ErrDenied
	}
	delete(s.tokens, id)
	if err := s.save(); err != nil {
		s.tokens[id] = old
		return err
	}
	return nil
}
