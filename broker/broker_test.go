// Copyright 2026 Cognity Computing & Consulting SRL
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// simDevices is a simulated device-control interface.
type simDevices struct{ calls []string }

func (s *simDevices) Execute(device, action string) error {
	s.calls = append(s.calls, device+"/"+action)
	return nil
}

// simConfirmer stands in for an out-of-band confirmation channel.
type simConfirmer struct {
	answer   bool
	requests []string
}

func (s *simConfirmer) Confirm(user, device, action string) bool {
	s.requests = append(s.requests, user+":"+device+"/"+action)
	return s.answer
}

type fixture struct {
	b       *Broker
	issuer  *Issuer
	devices *simDevices
	confirm *simConfirmer
	log     *bytes.Buffer
	clock   *time.Time
}

func newFixture(t *testing.T, confirm bool) *fixture {
	t.Helper()
	key := []byte("test-key-held-by-issuer-and-broker-only")
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	clock := &now
	nowFn := func() time.Time { return *clock }

	reg := NewRegistry()
	reg.Register("front_door", "unlock", Harmful)
	reg.Register("garage_door", "unlock", Harmful)
	reg.Register("living_room_light", "on", Low)

	f := &fixture{
		issuer:  NewIssuer(key, 2*time.Minute, nowFn),
		devices: &simDevices{},
		confirm: &simConfirmer{answer: confirm},
		log:     &bytes.Buffer{},
		clock:   clock,
	}
	b, err := New(Config{Registry: reg, Key: key, Executor: f.devices, Confirmer: f.confirm, Log: f.log, Now: nowFn})
	if err != nil {
		t.Fatal(err)
	}
	f.b = b
	return f
}

func expect(t *testing.T, d Decision, outcome Outcome, reason string) {
	t.Helper()
	if d.Outcome != outcome || d.Reason != reason {
		t.Fatalf("got %s/%s, want %s/%s (detail %q)", d.Outcome, d.Reason, outcome, reason, d.Detail)
	}
}

// A calendar invitation contains "unlock the front door". The model proposes
// the action; it is traced to untrusted content and carries no token.
func TestCalendarInjectionUnlockRejected(t *testing.T) {
	f := newFixture(t, true)
	d := f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Provenance: UntrustedContent})
	expect(t, d, Rejected, ReasonUntrustedProvenance)
	if len(f.devices.calls) != 0 {
		t.Fatalf("device was called: %v", f.devices.calls)
	}
	if len(f.confirm.requests) != 0 {
		t.Fatal("user was asked to confirm an injected action")
	}
}

// Even if the provenance label is wrong, an injected action has no token,
// because no authenticated user request was made.
func TestInjectionMislabelledAsUserStillRejected(t *testing.T) {
	f := newFixture(t, true)
	d := f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Provenance: UserRequest})
	expect(t, d, Rejected, ReasonNoToken)
	if len(f.devices.calls) != 0 {
		t.Fatal("device was called")
	}
}

// Paired legitimate test: the authenticated user asks to unlock the front
// door and confirms in the companion app.
func TestLegitimateUnlockAfterConfirmation(t *testing.T) {
	f := newFixture(t, true)
	tok, err := f.issuer.Issue("alice", "front_door", "unlock")
	if err != nil {
		t.Fatal(err)
	}
	d := f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: UserRequest})
	expect(t, d, Executed, ReasonOK)
	if got := strings.Join(f.devices.calls, ","); got != "front_door/unlock" {
		t.Fatalf("device calls = %q", got)
	}
	if got := strings.Join(f.confirm.requests, ","); got != "alice:front_door/unlock" {
		t.Fatalf("confirmation request = %q, want exact device and action", got)
	}
}

func TestLegitimateUnlockNotConfirmed(t *testing.T) {
	f := newFixture(t, false)
	tok, _ := f.issuer.Issue("alice", "front_door", "unlock")
	d := f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: UserRequest})
	expect(t, d, Rejected, ReasonNotConfirmed)
	if len(f.devices.calls) != 0 {
		t.Fatal("device was called without confirmation")
	}
}

// Redirect variant: injected content tries to change the target device of a
// legitimate request.
func TestRedirectToOtherDeviceRejected(t *testing.T) {
	f := newFixture(t, true)
	tok, _ := f.issuer.Issue("alice", "front_door", "unlock")
	d := f.b.Decide(Proposal{Device: "garage_door", Action: "unlock", Token: tok, Provenance: UserRequest})
	expect(t, d, Rejected, ReasonScope)
	if len(f.devices.calls) != 0 {
		t.Fatal("device was called")
	}
}

func TestReplayedTokenRejected(t *testing.T) {
	f := newFixture(t, true)
	tok, _ := f.issuer.Issue("alice", "front_door", "unlock")
	p := Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: UserRequest}
	expect(t, f.b.Decide(p), Executed, ReasonOK)
	expect(t, f.b.Decide(p), Rejected, ReasonReplay)
	if len(f.devices.calls) != 1 {
		t.Fatalf("device calls = %d, want 1", len(f.devices.calls))
	}
}

func TestForgedTokenRejected(t *testing.T) {
	f := newFixture(t, true)
	other := NewIssuer([]byte("attacker-key"), time.Minute, nil)
	forged, _ := other.Issue("alice", "front_door", "unlock")
	expect(t, f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: forged, Provenance: UserRequest}), Rejected, ReasonBadToken)

	// Tampered payload: rescope a valid light token to the door.
	tok, _ := f.issuer.Issue("alice", "living_room_light", "on")
	sig := tok[strings.Index(tok, ".")+1:]
	c := Claims{User: "alice", Device: "front_door", Action: "unlock", Nonce: "x", Expires: f.clock.Add(time.Minute)}
	raw, _ := json.Marshal(c)
	tampered := encode(raw) + "." + sig
	expect(t, f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: tampered, Provenance: UserRequest}), Rejected, ReasonBadToken)

	if len(f.devices.calls) != 0 {
		t.Fatal("device was called")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	f := newFixture(t, true)
	tok, _ := f.issuer.Issue("alice", "front_door", "unlock")
	*f.clock = f.clock.Add(3 * time.Minute)
	expect(t, f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: UserRequest}), Rejected, ReasonExpired)
}

func TestUnregisteredActionRejected(t *testing.T) {
	f := newFixture(t, true)
	tok, _ := f.issuer.Issue("alice", "front_door", "disable_alarm")
	expect(t, f.b.Decide(Proposal{Device: "front_door", Action: "disable_alarm", Token: tok, Provenance: UserRequest}), Rejected, ReasonUnknownAction)
}

func TestLowImpactActionNeedsNoConfirmation(t *testing.T) {
	f := newFixture(t, false)
	tok, _ := f.issuer.Issue("alice", "living_room_light", "on")
	expect(t, f.b.Decide(Proposal{Device: "living_room_light", Action: "on", Token: tok, Provenance: UserRequest}), Executed, ReasonOK)
	if len(f.confirm.requests) != 0 {
		t.Fatal("confirmation requested for low-impact action")
	}
}

// Every decision, allowed or rejected, is recorded as a JSON event.
func TestEveryDecisionLogged(t *testing.T) {
	f := newFixture(t, true)
	f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Provenance: UntrustedContent})
	tok, _ := f.issuer.Issue("alice", "front_door", "unlock")
	f.b.Decide(Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: UserRequest})

	lines := strings.Split(strings.TrimSpace(f.log.String()), "\n")
	if len(lines) != 2 || len(f.b.Events()) != 2 {
		t.Fatalf("got %d log lines, %d events; want 2", len(lines), len(f.b.Events()))
	}
	var first, second Decision
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if first.Outcome != Rejected || second.Outcome != Executed {
		t.Fatalf("events = %s, %s", first.Outcome, second.Outcome)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for missing dependencies")
	}
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
