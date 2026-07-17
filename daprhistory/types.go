// SPDX-License-Identifier: Apache-2.0
//
// Package daprhistory models the Dapr 1.18 "workflow history signing"
// state-store shapes described at:
//
//	https://v1-18.docs.dapr.io/developing-applications/building-blocks/workflow/workflow-history-signing/
//
// LIMITATION (see repository README for the full list): the public docs
// page documents the *signing scheme* -- which state-store keys exist, how
// events are batched and digested, how the hash chain is formed, and what a
// HistorySignature carries -- but it does not publish the wire schema of the
// underlying protobuf messages (HistoryEvent in particular is defined by
// the durabletask-go dependency, which this proof-of-concept does not
// vendor). The types in this file are therefore a deliberately reduced,
// hand-modeled shape that carries exactly what the documented signing
// algorithm and this adapter's AAC mapping need. They are NOT a
// byte-accurate reproduction of Dapr's protobuf, and no protobuf dependency
// is used anywhere in this module (by design -- see README).
package daprhistory

import (
	"encoding/json"
	"time"
)

// Event type discriminators. Dapr's workflow engine (durabletask) has many
// more event types than these; this PoC only needs to recognize the
// workflow-level start/terminal events to derive the AAC action_id,
// developer/workflow name, and effect.status. Any other EventType value is
// carried through untouched and simply does not affect terminal-state
// detection.
const (
	EventExecutionStarted    = "ExecutionStarted"
	EventExecutionCompleted  = "ExecutionCompleted"
	EventExecutionFailed     = "ExecutionFailed"
	EventExecutionTerminated = "ExecutionTerminated"
)

// Signature algorithm identifiers carried on HistorySignature.Algorithm.
// Dapr 1.18 defaults to Ed25519 and additionally documents ECDSA P-256 and
// RSA as supported; this PoC's VerifyChain implements Ed25519 verification
// only (matching the task scope) and returns a clear, typed error for any
// other algorithm value rather than silently accepting or rejecting it.
const (
	AlgorithmEd25519   = "ed25519"
	AlgorithmECDSAP256 = "ecdsa-p256"
	AlgorithmRSA       = "rsa"
)

// HistoryEvent mirrors one entry stored at a Dapr `history-NNNNNN`
// state-store key.
//
// Real Dapr history events are a oneof over many durabletask event kinds
// (ExecutionStarted, TaskScheduled, TaskCompleted, TimerFired, ...), each
// with its own attribute payload. This PoC substitutes a single flat
// struct: EventType names the kind, Attributes carries whatever
// kind-specific data a fixture needs, and InstanceID/Name are pulled out
// as first-class fields because the AAC mapping needs them directly
// (action_id and the workflow name in the dapr_workflow payload member).
type HistoryEvent struct {
	// Index is the event's position in the history, corresponding to the
	// NNNNNN suffix of its `history-NNNNNN` state-store key.
	Index uint64 `json:"index"`

	// EventType discriminates the kind of event. See the Event* constants
	// for the subset this adapter recognizes.
	EventType string `json:"event_type"`

	// Timestamp is the event's recorded time. Per the Dapr docs, time
	// binding for the whole history is "certificate validity checked
	// against the event timestamp" -- there is no external timestamping
	// authority, so this value is only as trustworthy as the signing
	// sidecar's own clock. See README LIMITATIONS.
	Timestamp time.Time `json:"timestamp"`

	// InstanceID is the Dapr workflow instance ID. In real Dapr this is
	// the actor/workflow instance identity under which the whole history
	// is stored, not a per-event field; it is modeled here as a per-event
	// field for fixture convenience, and this adapter requires it to be
	// consistent (or absent) across every event in one history.
	InstanceID string `json:"instance_id,omitempty"`

	// Name carries the workflow name; populated on ExecutionStarted in
	// real Dapr histories, left empty on other event types.
	Name string `json:"name,omitempty"`

	// Attributes is an opaque, event-kind-specific attribute bag standing
	// in for the real protobuf oneof payload. It participates in
	// Marshal() so tampering with it breaks the chain like any other
	// field.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Marshal returns the deterministic byte encoding of the event that is fed,
// length-prefixed, into eventsDigest (per the documented
// SHA-256-over-length-prefixed-events scheme).
//
// Real Dapr marshals the protobuf HistoryEvent; the exact determinism
// mechanism (deterministic binary protobuf marshaling, protojson, or
// something bespoke) is not stated in the public docs this PoC was built
// against (see README open question on "event canonicalization"). This PoC
// substitutes Go's encoding/json, which is deterministic for our purposes:
// struct fields serialize in declaration order (not reflection order) and
// Go's json package sorts map keys, so two calls over an unchanged struct
// value always produce identical bytes. This is a modeling substitute, not
// a claim about Dapr's actual wire encoding.
func (e HistoryEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// CertEntry mirrors one entry stored at a Dapr `sigcert-NNNNNN` (own,
// same-trust-domain cert) or `ext-sigcert-NNNNNN` (foreign, federated cert)
// state-store key.
//
// ASSUMPTION (see README open questions): the docs describe two distinct
// key prefixes but say a HistorySignature carries "an index reference into
// the certificate table" (singular). This PoC assumes sigcert-N and
// ext-sigcert-N share one flat index space -- i.e. index N is unique across
// both prefixes combined, and Foreign simply records which prefix a given
// index came from. If Dapr in fact keeps two independently-indexed tables,
// HistorySignature would need a second discriminator field to say which
// table CertIndex refers into; this is exactly the kind of ambiguity the
// PoC's README flags for the maintainers.
type CertEntry struct {
	Index   uint64 `json:"index"`
	Foreign bool   `json:"foreign"`

	// DER is the raw X.509 certificate (the SPIFFE SVID, or a federated
	// peer's cert for the `ext-sigcert-` case) in DER encoding.
	DER []byte `json:"der"`
}

// HistorySignature mirrors one entry stored at a Dapr `signature-NNNNNN`
// state-store key.
//
// The docs state a HistorySignature carries "signature bytes, an index
// reference into the certificate table, and the previous signature's
// digest" and that "each signature covers a contiguous range of events."
// The docs do not spell out how a signature records which event range it
// covers, or exactly what "the previous signature's digest" digests (the
// digest of the previous HistorySignature's signature bytes, versus the
// digest of the previous signing input/chain state, are both readings of
// that sentence). This PoC makes explicit, documented choices for both:
//
//   - FromEventIndex/ToEventIndex (inclusive) record the batch's event
//     range explicitly, rather than leaving batch boundaries implicit.
//   - PrevSignatureDigest is SHA-256 of the *previous HistorySignature's
//     Signature bytes* (empty/zero-length for the chain's first
//     signature). See VerifyChain and the README open questions.
type HistorySignature struct {
	Index uint64 `json:"index"`

	FromEventIndex uint64 `json:"from_event_index"`
	ToEventIndex   uint64 `json:"to_event_index"`

	// CertIndex references CertEntry.Index (see CertEntry's doc comment
	// on the flat-index-space assumption). Cert rotation is expressed by
	// later signatures referencing a higher CertIndex than earlier ones.
	CertIndex uint64 `json:"cert_index"`

	// Algorithm names the signature scheme; see the Algorithm* constants.
	// VerifyChain only implements Ed25519.
	Algorithm string `json:"algorithm"`

	// PrevSignatureDigest is SHA-256(previous signature's Signature
	// bytes), or empty for the chain's first signature. See the type doc
	// comment above for why this is a judgment call, not a documented fact.
	PrevSignatureDigest []byte `json:"prev_signature_digest,omitempty"`

	// Signature is the raw signature bytes over
	// SHA-256(PrevSignatureDigest || eventsDigest).
	Signature []byte `json:"signature"`
}
