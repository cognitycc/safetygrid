# SafetyGrid

SafetyGrid is an open initiative to make the LLM input channel of products with digital elements governed, testable and evidenced under the EU Cyber Resilience Act. It is aligned with MITRE ATLAS and the OWASP Top 10 for LLM Applications and proposes no new taxonomy.

Concept paper: Sampokilis, P. (2026). *Securing the AI Input Channel* (Version 1.0). Zenodo. https://doi.org/10.5281/zenodo.23090364

## Status

This repository currently contains an **early prototype of the tool broker and action registry** (work item E2 in the StandICT.eu 2029 Open Call 3 work plan). It is a starting point for the reference implementation, not a finished component.

## What the broker does

The broker sits between a language model and a device-control interface. The model can only propose actions; the broker decides.

- **Action registry.** An allow-list of device actions, each classed as low impact or harmful. Unregistered actions are rejected.
- **Token-bound actions.** When an authenticated user makes a request, an issuer creates a signed token (HMAC-SHA256) scoped to one device and one action, with an expiry and a single-use nonce. The broker rejects proposals with no token, an invalid or forged token, an expired or replayed token, or a token whose device or action differs from the proposal.
- **Untrusted content.** Proposals labelled as derived from untrusted content (email, calendar entry, web page, document, played audio) are rejected.
- **Confirmation for harmful functions.** Harmful actions also require confirmation through a `Confirmer`, which stands for a channel the model cannot write to. The request names the exact device and action.
- **Decision log.** Every decision, allowed or rejected, is recorded with a reason code and written as a JSON line.

## Tests

`go test ./...` runs the worked example from the proposal against simulated devices:

| Test | Expected result |
|---|---|
| Calendar invitation contains "unlock the front door" | Rejected, no device call, no confirmation prompt |
| Same injection mislabelled as a user request | Rejected: no authorisation token |
| Authenticated user asks to unlock the front door and confirms | Executed and logged |
| Same request, user declines confirmation | Rejected |
| Redirect: front-door token used for the garage door | Rejected: scope mismatch |
| Replayed, forged, tampered or expired token | Rejected |
| Unregistered action | Rejected |
| Low-impact action | Executed without confirmation |

`go run ./cmd/broker-demo` prints the three main cases as JSON decision events.

## Not yet implemented

Stated plainly so that nothing here is read as more than it is:

- No language model is connected; proposals are scripted.
- The provenance label is supplied by the caller and trusted as given. Signed provenance from a content labeller is planned. The token check does not rely on the label, so an injected action without a user request is still rejected.
- User authentication, the companion-app confirmation channel and speaker verification are represented by interfaces only.
- Isolation of the real device-control interface, so that only the broker can reach it, is a deployment concern not covered here.
- Used-token state is held in memory only.
- The inspection agent, edge enforcement, audio channel and signature store are separate work items and are not in this repository yet.

## Licence

Code: Apache License 2.0. Documentation and specifications: CC BY 4.0.

Maintained by Cognity Computing & Consulting SRL. Contact: panos@cognitycc.com
