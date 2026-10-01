// Copyright 2026 Cognity Computing & Consulting SRL
// SPDX-License-Identifier: Apache-2.0

package broker

// Impact classifies an action by the consequence of executing it.
type Impact int

const (
	// Low impact actions execute once authorised.
	Low Impact = iota
	// Harmful actions additionally require confirmation through a
	// channel the model cannot write to.
	Harmful
)

func (i Impact) String() string {
	if i == Harmful {
		return "harmful"
	}
	return "low"
}

// ActionKey identifies one action on one device.
type ActionKey struct {
	Device string
	Action string
}

// Registry is an allow-list of device actions and their impact class.
// Anything not registered is rejected (fail-closed).
type Registry struct {
	entries map[ActionKey]Impact
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[ActionKey]Impact{}}
}

// Register adds an action to the allow-list.
func (r *Registry) Register(device, action string, impact Impact) {
	r.entries[ActionKey{device, action}] = impact
}

// Lookup returns the impact class of a registered action.
func (r *Registry) Lookup(device, action string) (Impact, bool) {
	i, ok := r.entries[ActionKey{device, action}]
	return i, ok
}
