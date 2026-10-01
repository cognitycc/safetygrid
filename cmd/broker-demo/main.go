// Copyright 2026 Cognity Computing & Consulting SRL
// SPDX-License-Identifier: Apache-2.0

// Command broker-demo runs the calendar-invitation worked example against
// simulated devices and prints each broker decision as a JSON line.
// No language model is involved; proposals are scripted.
package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/cognitycc/safetygrid/broker"
)

type devices struct{}

func (devices) Execute(device, action string) error {
	fmt.Fprintf(os.Stderr, "  device: %s %s\n", device, action)
	return nil
}

type autoConfirm struct{}

func (autoConfirm) Confirm(user, device, action string) bool {
	fmt.Fprintf(os.Stderr, "  confirm: %s asked to approve %s %s -> yes\n", user, device, action)
	return true
}

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	reg := broker.NewRegistry()
	reg.Register("front_door", "unlock", broker.Harmful)
	reg.Register("garage_door", "unlock", broker.Harmful)

	b, err := broker.New(broker.Config{Registry: reg, Key: key, Executor: devices{}, Confirmer: autoConfirm{}, Log: os.Stdout})
	if err != nil {
		panic(err)
	}
	issuer := broker.NewIssuer(key, 2*time.Minute, nil)

	fmt.Fprintln(os.Stderr, "1. Calendar invitation says: unlock the front door")
	b.Decide(broker.Proposal{Device: "front_door", Action: "unlock", Provenance: broker.UntrustedContent})

	fmt.Fprintln(os.Stderr, "2. Authenticated user asks to unlock the front door")
	tok, err := issuer.Issue("alice", "front_door", "unlock")
	if err != nil {
		panic(err)
	}
	b.Decide(broker.Proposal{Device: "front_door", Action: "unlock", Token: tok, Provenance: broker.UserRequest})

	fmt.Fprintln(os.Stderr, "3. Injected content redirects a new legitimate request to the garage")
	tok2, _ := issuer.Issue("alice", "front_door", "unlock")
	b.Decide(broker.Proposal{Device: "garage_door", Action: "unlock", Token: tok2, Provenance: broker.UserRequest})
}
