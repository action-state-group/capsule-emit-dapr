// SPDX-License-Identifier: Apache-2.0
package aacexport

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"

	"github.com/action-state-group/capsule-emit-dapr/daprhistory"
	"github.com/action-state-group/capsule-emit-dapr/internal/testfixture"
)

// registryPath locates this repository's vendored copy of the profile's
// spec/REGISTRY.md, relative to this test file. It is deliberately NOT
// registries.FindRegistryMD() (which walks up from CWD looking for
// spec/REGISTRY.md) and NOT a path into a sibling checkout: this repository
// must clone and `go test` standalone, with no adjacent agent-action-capsule
// working copy and no AAC_REGISTRY_PATH set.
//
// testdata/REGISTRY.md is a pinned copy; see NOTICE for provenance. If the
// upstream registry gains values this exporter emits, refresh it.
func registryPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// aacexport/export_test.go -> ../testdata/REGISTRY.md
	path := filepath.Join(filepath.Dir(thisFile), "..", "testdata", "REGISTRY.md")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolving REGISTRY.md path: %v", err)
	}
	return abs
}

func loadRegs(t *testing.T) map[string]map[string]bool {
	t.Helper()
	regs, err := registries.Load(registryPath(t))
	if err != nil {
		t.Fatalf("loading REGISTRY.md: %v", err)
	}
	return regs
}

func buildValidHistory(t *testing.T, instanceID string, terminal string) ([]daprhistory.HistoryEvent, []daprhistory.HistorySignature, []daprhistory.CertEntry) {
	t.Helper()
	signer, err := testfixture.NewSignerCert(0, "example.org", "default", "order-agent")
	if err != nil {
		t.Fatalf("NewSignerCert: %v", err)
	}
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory(instanceID, "BookVenue", start, terminal)
	sigs, err := testfixture.SignChain(events, []testfixture.Batch{{From: 0, To: uint64(len(events) - 1), Signer: signer}})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}
	return events, sigs, []daprhistory.CertEntry{signer.CertEntry(false)}
}

func TestFromSignedHistory_HappyPath(t *testing.T) {
	events, sigs, certs := buildValidHistory(t, "wf-happy-1", daprhistory.EventExecutionCompleted)

	capsule, id1, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{})
	if err != nil {
		t.Fatalf("FromSignedHistory: %v", err)
	}
	if id1 == "" {
		t.Fatal("capsule_id is empty")
	}

	// capsule_id must be stable across repeated builds of the same input.
	_, id2, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{})
	if err != nil {
		t.Fatalf("FromSignedHistory (second call): %v", err)
	}
	if id1 != id2 {
		t.Errorf("capsule_id not stable: %q vs %q", id1, id2)
	}

	if capsule["action_id"] != "wf-happy-1" {
		t.Errorf("action_id = %v, want wf-happy-1", capsule["action_id"])
	}
	// A signed history records execution, not a decision: it carries no
	// disposition, so the honest action_type is "fyi". Emitting "decide"
	// here would assert a disposition was required and then not say how it
	// was disposed -- an overclaim Class 1 verification does not catch.
	if capsule["action_type"] != "fyi" {
		t.Errorf("action_type = %v, want fyi", capsule["action_type"])
	}
	if _, present := capsule["disposition"]; present {
		t.Errorf("disposition present: a Dapr history carries no disposition; got %v", capsule["disposition"])
	}
	effect, ok := capsule["effect"].(map[string]interface{})
	if !ok || effect["status"] != "confirmed" {
		t.Fatalf("effect.status = %v, want confirmed", capsule["effect"])
	}
	rd, _ := effect["response_digest"].(string)
	if !isHex64(rd) {
		t.Errorf("effect.response_digest = %q, want 64-lowercase-hex", rd)
	}

	regs := loadRegs(t)
	res := verify.Verify(capsule, nil, regs)
	if !res.OK {
		t.Errorf("verify.Verify: OK = false, findings: %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.Severity == "error" {
			t.Errorf("unexpected error finding: %+v", f)
		}
	}
}

func TestFromSignedHistory_RefusesOnBrokenChain(t *testing.T) {
	events, sigs, certs := buildValidHistory(t, "wf-broken-1", daprhistory.EventExecutionCompleted)

	tampered := append([]daprhistory.HistoryEvent(nil), events...)
	tampered[1].Attributes = map[string]string{"activity": "charge_card", "amount": "999999"}

	_, _, err := FromSignedHistory(tampered, sigs, certs, daprhistory.VerifyOptions{}, Config{})
	if err == nil {
		t.Fatal("FromSignedHistory: expected an error for a tampered/broken chain, got nil")
	}
}

func TestFromSignedHistory_InProgressWorkflowNotConfirmed(t *testing.T) {
	// No terminal event yet: the workflow is still running.
	events, sigs, certs := buildValidHistory(t, "wf-running-1", "")

	capsule, _, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{})
	if err != nil {
		t.Fatalf("FromSignedHistory: %v", err)
	}
	effect := capsule["effect"].(map[string]interface{})
	if effect["status"] != "dispatched" {
		t.Errorf("effect.status = %v, want dispatched for an in-progress workflow", effect["status"])
	}
	if _, has := effect["response_digest"]; has {
		t.Errorf("response_digest must be absent for a non-confirmed effect")
	}

	regs := loadRegs(t)
	res := verify.Verify(capsule, nil, regs)
	if !res.OK {
		t.Errorf("verify.Verify: OK = false, findings: %+v", res.Findings)
	}
}

func TestFromSignedHistory_OperatorOverride(t *testing.T) {
	events, sigs, certs := buildValidHistory(t, "wf-override-1", daprhistory.EventExecutionCompleted)

	capsule, _, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{OperatorOverride: "tenant-42"})
	if err != nil {
		t.Fatalf("FromSignedHistory: %v", err)
	}
	if capsule["operator"] != "tenant-42" {
		t.Errorf("operator = %v, want tenant-42 (override)", capsule["operator"])
	}
}

// TestBuildEffect_ConfirmedWithoutDigestRejected directly exercises the
// load-bearing confirmed-effect binding invariant: buildEffect must refuse
// to construct an effect record with status=confirmed and no valid
// response_digest. FromSignedHistory can never actually hit this path with
// a verified chain (a verified "confirmed" workflow always yields a valid
// chain-head digest), so the invariant is tested at the unit directly, the
// same way capsule-profile's buildCapsule tests its analogous guard.
func TestBuildEffect_ConfirmedWithoutDigestRejected(t *testing.T) {
	_, err := buildEffect("confirmed", "", EffectAttestation)
	if err == nil {
		t.Fatal("buildEffect: expected an error for confirmed status with no response_digest, got nil")
	}
	if _, ok := err.(*ConfirmedWithoutDigestError); !ok {
		t.Errorf("buildEffect: error = %T, want *ConfirmedWithoutDigestError", err)
	}

	_, err = buildEffect("confirmed", "not-64-hex", EffectAttestation)
	if err == nil {
		t.Fatal("buildEffect: expected an error for confirmed status with a malformed response_digest, got nil")
	}

	// The valid case must succeed.
	digest := "aa11223344556677889900112233445566778899001122334455667788990011"
	effect, err := buildEffect("confirmed", digest, EffectAttestation)
	if err != nil {
		t.Fatalf("buildEffect: unexpected error for a valid confirmed effect: %v", err)
	}
	if effect["response_digest"] != digest {
		t.Errorf("response_digest = %v, want %v", effect["response_digest"], digest)
	}
}

// TestActionTypeOverride: "decide" is available to callers who know out of
// band that a disposition was genuinely required, and invalid values are
// refused at the producer rather than deferred to a verifier that would not
// reject them anyway.
func TestActionTypeOverride(t *testing.T) {
	events, sigs, certs := buildValidHistory(t, "wf-actiontype-1", daprhistory.EventExecutionCompleted)

	capsule, _, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{ActionType: "decide"})
	if err != nil {
		t.Fatalf("FromSignedHistory(decide): %v", err)
	}
	if capsule["action_type"] != "decide" {
		t.Errorf("action_type = %v, want decide", capsule["action_type"])
	}

	if _, _, err := FromSignedHistory(events, sigs, certs, daprhistory.VerifyOptions{}, Config{ActionType: "maybe"}); err == nil {
		t.Error("expected refusal for action_type \"maybe\", got nil error")
	}
}
