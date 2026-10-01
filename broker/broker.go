// Copyright 2026 Cognity Computing & Consulting SRL
// SPDX-License-Identifier: Apache-2.0

// Package broker is an early prototype of a tool broker that sits between
// a language model and a device-control interface. The model can only
// propose actions; the broker permits or rejects them.
package broker

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

// Provenance records where a proposed action came from, as labelled by the
// orchestrator. This prototype trusts the label it is given; label integrity
// (signed provenance from a content labeller) is not implemented. The token
// check below does not depend on the label.
type Provenance string

const (
	// UserRequest: the action follows an authenticated user request.
	UserRequest Provenance = "user-request"
	// UntrustedContent: the action was derived from content the assistant
	// processed (email, calendar entry, web page, document, played audio).
	UntrustedContent Provenance = "untrusted-content"
)

// Proposal is an action proposed by the model.
type Proposal struct {
	Device     string
	Action     string
	Token      string
	Provenance Provenance
}

// Outcome of a broker decision.
type Outcome string

// Outcomes.
const (
	Executed Outcome = "executed"
	Rejected Outcome = "rejected"
)

// Reason codes recorded with each decision.
const (
	ReasonOK                  = "ok"
	ReasonUnknownAction       = "action-not-registered"
	ReasonUntrustedProvenance = "untrusted-provenance"
	ReasonNoToken             = "no-authorisation-token"
	ReasonBadToken            = "token-invalid"
	ReasonExpired             = "token-expired"
	ReasonReplay              = "token-replayed"
	ReasonScope               = "token-scope-mismatch"
	ReasonNotConfirmed        = "confirmation-not-given"
	ReasonExecFailed          = "execution-failed"
)

// Decision is returned for every proposal and recorded as an event.
type Decision struct {
	Time    time.Time `json:"time"`
	Device  string    `json:"device"`
	Action  string    `json:"action"`
	Impact  string    `json:"impact,omitempty"`
	User    string    `json:"user,omitempty"`
	Outcome Outcome   `json:"outcome"`
	Reason  string    `json:"reason"`
	Detail  string    `json:"detail,omitempty"`
}

// Executor is the device-control interface. Only the broker holds it.
// Preventing other components from reaching the real device interface
// (network or process isolation) is a deployment concern not covered here.
type Executor interface {
	Execute(device, action string) error
}

// Confirmer asks the user to confirm a harmful action through a channel the
// model cannot write to (companion app, physical button). The request names
// the exact device and action.
type Confirmer interface {
	Confirm(user, device, action string) bool
}

// Broker permits or rejects model-proposed actions.
type Broker struct {
	reg     *Registry
	ver     *verifier
	exec    Executor
	confirm Confirmer
	now     func() time.Time
	mu      sync.Mutex
	log     io.Writer
	events  []Decision
}

// Config holds broker dependencies.
type Config struct {
	Registry  *Registry
	Key       []byte // shared with the Issuer; never given to the model
	Executor  Executor
	Confirmer Confirmer
	Log       io.Writer // JSON lines; optional
	Now       func() time.Time
}

// New returns a broker, or an error if a required dependency is missing.
func New(c Config) (*Broker, error) {
	if c.Registry == nil || c.Executor == nil || c.Confirmer == nil || len(c.Key) == 0 {
		return nil, errors.New("broker: registry, key, executor and confirmer are required")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Broker{
		reg: c.Registry, exec: c.Executor, confirm: c.Confirmer, now: c.Now, log: c.Log,
		ver: &verifier{key: c.Key, now: c.Now, used: map[string]time.Time{}},
	}, nil
}

// Decide evaluates a proposal. Checks run in a fixed order, the first failure
// rejects, and anything not explicitly allowed is rejected.
func (b *Broker) Decide(p Proposal) Decision {
	d := Decision{Time: b.now(), Device: p.Device, Action: p.Action, Outcome: Rejected}

	impact, ok := b.reg.Lookup(p.Device, p.Action)
	if !ok {
		return b.record(d, ReasonUnknownAction, "")
	}
	d.Impact = impact.String()

	if p.Provenance != UserRequest {
		return b.record(d, ReasonUntrustedProvenance, string(p.Provenance))
	}
	if p.Token == "" {
		return b.record(d, ReasonNoToken, "")
	}
	c, err := b.ver.verify(p.Token)
	switch {
	case errors.Is(err, ErrExpired):
		return b.record(d, ReasonExpired, "")
	case errors.Is(err, ErrReplayed):
		return b.record(d, ReasonReplay, "")
	case err != nil:
		return b.record(d, ReasonBadToken, err.Error())
	}
	d.User = c.User
	if c.Device != p.Device || c.Action != p.Action {
		return b.record(d, ReasonScope, "token is for "+c.Device+"/"+c.Action)
	}
	if impact == Harmful && !b.confirm.Confirm(c.User, p.Device, p.Action) {
		return b.record(d, ReasonNotConfirmed, "")
	}
	b.ver.consume(c)
	if err := b.exec.Execute(p.Device, p.Action); err != nil {
		return b.record(d, ReasonExecFailed, err.Error())
	}
	d.Outcome = Executed
	return b.record(d, ReasonOK, "")
}

func (b *Broker) record(d Decision, reason, detail string) Decision {
	d.Reason, d.Detail = reason, detail
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, d)
	if b.log != nil {
		if line, err := json.Marshal(d); err == nil {
			_, _ = b.log.Write(append(line, '\n'))
		}
	}
	return d
}

// Events returns a copy of all decisions recorded so far.
func (b *Broker) Events() []Decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Decision(nil), b.events...)
}
