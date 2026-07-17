// SPDX-License-Identifier: Apache-2.0
//
// Package aacexport projects a signature-chain-verified Dapr 1.18 workflow
// history into an Agent Action Capsule (AAC), per
// draft-mih-scitt-agent-action-capsule-02.
//
// FromSignedHistory refuses to export a history whose chain does not
// verify: daprhistory.VerifyChain runs first, and any error it returns is
// wrapped and returned as-is, without producing a capsule.
package aacexport

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"

	"github.com/action-state-group/dapr-aac-export/daprhistory"
)

// SpecVersion and FormatVersion are the profile versions this exporter
// targets (draft-mih-scitt-agent-action-capsule-02, §"Identity and parties").
const (
	SpecVersion   = "draft-mih-scitt-agent-action-capsule-02"
	FormatVersion = "2"
)

// EffectAttestation is the grade this adapter records on every effect it
// exports: "runtime_claimed" ("the executing runtime asserted completion;
// the capsule records that claim, not an observation" — spec §Effect
// Record). This is a deliberate, conservative choice, not a default we
// picked by omission: this adapter reads an already-signed, already-closed
// Dapr history after the fact. It does not sit on the Dapr execution path
// and does not itself observe the effect boundary the way a policy gate
// would ("gate_executed" — "the engine observed the effect boundary
// directly"). Grading the claim as gate_executed would overclaim what this
// PoC actually witnessed: a cryptographically verified *record* of
// completion, not a live observation of it. See README open questions.
const EffectAttestation = "runtime_claimed"

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHex64(s string) bool { return hex64RE.MatchString(s) }

// ConfirmedWithoutDigestError is returned when a caller (directly, or via
// FromSignedHistory) attempts to build an effect record with
// status=confirmed but no valid 64-lowercase-hex response_digest. The
// profile's confirmed-effect binding (§Effect Record) makes this a hard
// producer error, never a warning: "a producer MUST NOT emit
// status: confirmed without a response_digest over the actually observed
// response."
type ConfirmedWithoutDigestError struct{}

func (e *ConfirmedWithoutDigestError) Error() string {
	return "effect.status \"confirmed\" requires a 64-lowercase-hex response_digest (§Effect Record, confirmed-effect binding)"
}

// DefaultActionType is the `action_type` this adapter emits unless a caller
// overrides it: "fyi" (informational).
//
// This is the same conservative reasoning as EffectAttestation, applied to
// §"Identity and parties": action_type is "fyi" (informational) or "decide"
// (*a disposition was required*). A Dapr signed workflow history is a record
// of execution, not of a decision — it carries no gate, no approver, and no
// human-in-the-loop signal. Nothing this adapter can read establishes that a
// disposition was ever required, let alone how it was disposed.
//
// Emitting "decide" with no `disposition` block would therefore assert that a
// decision was required and then decline to say how it went. Class 1
// verification would not catch it (the verifier only checks the enum), which
// is exactly why the producer must not do it: this profile's whole thesis is
// the may/did distinction and the refusal to overclaim. A history export
// says "this ran" — that is "fyi".
//
// Callers with out-of-band knowledge that a workflow really did pass a gate
// SHOULD set Config.ActionType to "decide" AND supply the corresponding
// disposition block; that information does not exist in Dapr's history today.
const DefaultActionType = "fyi"

// Config carries producer-side overrides for FromSignedHistory.
type Config struct {
	// OperatorOverride, if non-empty, is used as the capsule's `operator`
	// field instead of the SPIFFE trust domain extracted from the signing
	// certificate. Dapr's SPIFFE trust domain is a reasonable default
	// stand-in for "the accountable tenant" but is not guaranteed to be
	// the right value for every deployment (a shared trust domain can
	// host multiple tenants); operators that need a different value
	// should set this.
	OperatorOverride string

	// ActionType, if non-empty, overrides DefaultActionType. It MUST be
	// "fyi" or "decide". Set "decide" only when the caller knows out of
	// band that a disposition was genuinely required for this workflow.
	ActionType string
}

// effectStatusFromEventType derives effect.status from the terminal event
// type of a Dapr workflow history. Only ExecutionStarted/Completed/
// Failed/Terminated are recognized by this PoC (see daprhistory package
// doc); any other terminal event type falls through to "dispatched"
// (sent, result not yet observed as complete or failed).
func effectStatusFromEventType(eventType string) string {
	switch eventType {
	case daprhistory.EventExecutionCompleted:
		return "confirmed"
	case daprhistory.EventExecutionFailed, daprhistory.EventExecutionTerminated:
		return "failed"
	default:
		return "dispatched"
	}
}

// deriveEffectMode mirrors verify.go's deriveEffectMode (§Assurance) so the
// capsule this package builds carries an assurance block that the Class-1
// verifier re-derives byte-for-byte, with no overclaim finding.
func deriveEffectMode(effect map[string]interface{}) string {
	if effect == nil {
		return "not_applicable"
	}
	status, _ := effect["status"].(string)
	if status == "planned" {
		return "not_applicable"
	}
	if status == "confirmed" {
		if rd, ok := effect["response_digest"].(string); ok && isHex64(rd) {
			return "confirmed"
		}
		return "dispatched_unconfirmed"
	}
	return "dispatched_unconfirmed"
}

// buildEffect assembles the Effect Record, enforcing the confirmed-effect
// binding: status="confirmed" REQUIRES a 64-lowercase-hex response_digest.
func buildEffect(status, responseDigest, attestation string) (map[string]interface{}, error) {
	if status == "confirmed" && !isHex64(responseDigest) {
		return nil, &ConfirmedWithoutDigestError{}
	}
	effect := map[string]interface{}{
		"status":             status,
		"effect_attestation": attestation,
	}
	if responseDigest != "" {
		effect["response_digest"] = responseDigest
	}
	return effect, nil
}

// FromSignedHistory verifies a Dapr 1.18 signed workflow history end to end
// and, only if the chain verifies, projects it into an Agent Action Capsule.
//
// The mapping (see README for the full table and open questions):
//
//   - developer         <- the SPIFFE ID (URI SAN) of the certificate that
//     produced the history's final signature
//   - operator          <- the SPIFFE trust domain, or cfg.OperatorOverride
//   - action_id         <- the Dapr workflow instance ID
//   - timestamp         <- the last history event's timestamp (RFC3339 UTC, "Z")
//   - action_type       <- "fyi" (DefaultActionType), or cfg.ActionType
//   - effect.status     <- "confirmed" when the workflow completed
//   - effect.response_digest <- the final signature-chain head digest
//   - dapr_workflow     <- a namespaced payload member carrying chain head,
//     event count, SPIFFE ID, trust domain, workflow name, and
//     signature/cert table sizes
//
// FromSignedHistory refuses to export (returns a non-nil error and no
// capsule) when the signature chain does not verify.
func FromSignedHistory(
	events []daprhistory.HistoryEvent,
	sigs []daprhistory.HistorySignature,
	certs []daprhistory.CertEntry,
	verifyOpts daprhistory.VerifyOptions,
	cfg Config,
) (capsule map[string]interface{}, capsuleID string, err error) {
	result, err := daprhistory.VerifyChain(events, sigs, certs, verifyOpts)
	if err != nil {
		return nil, "", fmt.Errorf("refusing to export: signed history chain does not verify: %w", err)
	}

	operator := cfg.OperatorOverride
	if operator == "" {
		operator = result.TrustDomain
	}
	if operator == "" {
		return nil, "", fmt.Errorf("refusing to export: no operator available (SPIFFE trust domain was empty and no OperatorOverride was configured)")
	}
	if result.SPIFFEID == "" {
		return nil, "", fmt.Errorf("refusing to export: no SPIFFE ID available for developer")
	}
	if result.InstanceID == "" {
		return nil, "", fmt.Errorf("refusing to export: no workflow instance ID available for action_id")
	}

	actionType := cfg.ActionType
	if actionType == "" {
		actionType = DefaultActionType
	}
	if actionType != "fyi" && actionType != "decide" {
		return nil, "", fmt.Errorf("refusing to export: action_type MUST be \"fyi\" or \"decide\" (§Identity and parties), got %q", actionType)
	}

	status := effectStatusFromEventType(result.LastEventType)
	responseDigest := ""
	if status == "confirmed" {
		responseDigest = hex.EncodeToString(result.ChainHeadDigest[:])
	}

	effect, err := buildEffect(status, responseDigest, EffectAttestation)
	if err != nil {
		return nil, "", err
	}

	assurance := map[string]interface{}{
		"attestation_mode": "self_attested", // no Receipt verified at build time (§Assurance)
		"effect_mode":      deriveEffectMode(effect),
		"ledger_mode":      "standalone", // no chain block: this is a single, unlinked capsule export
	}

	daprWorkflow := map[string]interface{}{
		"chain_head_digest": hex.EncodeToString(result.ChainHeadDigest[:]),
		"event_count":       strconv.Itoa(result.EventCount), // exact decimal string, never a JSON number (§5.1)
		"signature_count":   strconv.Itoa(result.SignatureCount),
		"cert_count":        strconv.Itoa(result.CertCount),
		"spiffe_id":         result.SPIFFEID,
		"trust_domain":      result.TrustDomain,
	}
	if result.WorkflowName != "" {
		daprWorkflow["workflow_name"] = result.WorkflowName
	}

	built := map[string]interface{}{
		"spec_version":   SpecVersion,
		"format_version": FormatVersion,
		"action_id":      result.InstanceID,
		"action_type":    actionType,
		"operator":       operator,
		"developer":      result.SPIFFEID,
		"timestamp":      result.LastEventTime.UTC().Format(time.RFC3339),
		"effect":         effect,
		"assurance":      assurance,
		"dapr_workflow":  daprWorkflow,
	}

	id, err := canonical.ComputeCapsuleID(built)
	if err != nil {
		return nil, "", fmt.Errorf("computing capsule_id: %w", err)
	}
	built["capsule_id"] = id

	return built, id, nil
}
