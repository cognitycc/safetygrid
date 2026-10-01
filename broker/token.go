// Copyright 2026 Cognity Computing & Consulting SRL
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Claims bind a token to one authenticated user request, scoped to a
// single device and action. The scope is the request, not an inferred intent.
type Claims struct {
	User    string    `json:"user"`
	Device  string    `json:"device"`
	Action  string    `json:"action"`
	Nonce   string    `json:"nonce"`
	Expires time.Time `json:"exp"`
}

// Token errors.
var (
	ErrMalformed = errors.New("token malformed")
	ErrSignature = errors.New("token signature invalid")
	ErrExpired   = errors.New("token expired")
	ErrReplayed  = errors.New("token already used")
)

// Issuer creates a token when an authenticated user makes a request.
// In this prototype the issuer and the broker share an HMAC key, which the
// model and other components never hold. User authentication itself is
// outside the scope of this package.
type Issuer struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// NewIssuer returns an issuer using key and token lifetime ttl.
func NewIssuer(key []byte, ttl time.Duration, now func() time.Time) *Issuer {
	if now == nil {
		now = time.Now
	}
	return &Issuer{key: key, ttl: ttl, now: now}
}

// Issue returns a signed, single-use token for one device action.
func (i *Issuer) Issue(user, device, action string) (string, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	c := Claims{User: user, Device: device, Action: action, Nonce: hex.EncodeToString(n), Expires: i.now().Add(i.ttl)}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + sign(i.key, p), nil
}

func sign(key []byte, p string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// verifier checks signature, expiry and single use.
type verifier struct {
	key  []byte
	now  func() time.Time
	mu   sync.Mutex
	used map[string]time.Time
}

func (v *verifier) verify(tok string) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return c, ErrMalformed
	}
	if !hmac.Equal([]byte(sign(v.key, parts[0])), []byte(parts[1])) {
		return c, ErrSignature
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, ErrMalformed
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, ErrMalformed
	}
	if !v.now().Before(c.Expires) {
		return c, ErrExpired
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, seen := v.used[c.Nonce]; seen {
		return c, ErrReplayed
	}
	return c, nil
}

// consume marks a token as used. It is called only when an action executes.
// Used nonces are kept in memory; persistence and pruning are not implemented.
func (v *verifier) consume(c Claims) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.used[c.Nonce] = c.Expires
}
