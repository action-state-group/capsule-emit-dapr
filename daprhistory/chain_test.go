// SPDX-License-Identifier: Apache-2.0
package daprhistory_test

import (
	"testing"
	"time"

	"github.com/action-state-group/dapr-aac-export/daprhistory"
	"github.com/action-state-group/dapr-aac-export/internal/testfixture"
)

func mustSigner(t *testing.T, index uint64, trustDomain, ns, appID string) *testfixture.SignerCert {
	t.Helper()
	s, err := testfixture.NewSignerCert(index, trustDomain, ns, appID)
	if err != nil {
		t.Fatalf("NewSignerCert: %v", err)
	}
	return s
}

func TestVerifyChain_HappyPath(t *testing.T) {
	signer := mustSigner(t, 0, "example.org", "default", "order-agent")
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-1", "BookVenue", start, daprhistory.EventExecutionCompleted)

	sigs, err := testfixture.SignChain(events, []testfixture.Batch{
		{From: 0, To: 3, Signer: signer},
	})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}

	certs := []daprhistory.CertEntry{signer.CertEntry(false)}

	result, err := daprhistory.VerifyChain(events, sigs, certs, daprhistory.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain: unexpected error: %v", err)
	}
	if !result.LastEventTime.Equal(start.Add(3 * time.Second)) {
		t.Errorf("LastEventTime = %v, want %v", result.LastEventTime, start.Add(3*time.Second))
	}
	if result.LastEventType != daprhistory.EventExecutionCompleted {
		t.Errorf("LastEventType = %q, want ExecutionCompleted", result.LastEventType)
	}
	if result.InstanceID != "wf-instance-1" {
		t.Errorf("InstanceID = %q, want wf-instance-1", result.InstanceID)
	}
	if result.WorkflowName != "BookVenue" {
		t.Errorf("WorkflowName = %q, want BookVenue", result.WorkflowName)
	}
	if result.SPIFFEID != signer.SPIFFEID {
		t.Errorf("SPIFFEID = %q, want %q", result.SPIFFEID, signer.SPIFFEID)
	}
	if result.TrustDomain != "example.org" {
		t.Errorf("TrustDomain = %q, want example.org", result.TrustDomain)
	}
	if result.EventCount != 4 {
		t.Errorf("EventCount = %d, want 4", result.EventCount)
	}
	if result.SignatureCount != 1 {
		t.Errorf("SignatureCount = %d, want 1", result.SignatureCount)
	}
	var zero [32]byte
	if result.ChainHeadDigest == zero {
		t.Errorf("ChainHeadDigest is all-zero, expected a real SHA-256 digest")
	}
}

func TestVerifyChain_CertRotationMidChain(t *testing.T) {
	signerA := mustSigner(t, 0, "example.org", "default", "order-agent")
	signerB := mustSigner(t, 1, "example.org", "default", "order-agent") // rotated key/cert, same identity string shape

	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-2", "BookVenue", start, daprhistory.EventExecutionCompleted)

	sigs, err := testfixture.SignChain(events, []testfixture.Batch{
		{From: 0, To: 1, Signer: signerA},
		{From: 2, To: 3, Signer: signerB},
	})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}

	certs := []daprhistory.CertEntry{signerA.CertEntry(false), signerB.CertEntry(false)}

	result, err := daprhistory.VerifyChain(events, sigs, certs, daprhistory.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain: unexpected error with cert rotation: %v", err)
	}
	if result.SPIFFEID != signerB.SPIFFEID {
		t.Errorf("SPIFFEID = %q, want the rotated-to signer %q", result.SPIFFEID, signerB.SPIFFEID)
	}
	if result.SignatureCount != 2 {
		t.Errorf("SignatureCount = %d, want 2", result.SignatureCount)
	}
}

func TestVerifyChain_TamperedEventBreaksChain(t *testing.T) {
	signer := mustSigner(t, 0, "example.org", "default", "order-agent")
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-3", "BookVenue", start, daprhistory.EventExecutionCompleted)

	sigs, err := testfixture.SignChain(events, []testfixture.Batch{{From: 0, To: 3, Signer: signer}})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}
	certs := []daprhistory.CertEntry{signer.CertEntry(false)}

	// Tamper with an already-signed event.
	tampered := append([]daprhistory.HistoryEvent(nil), events...)
	tampered[1].Attributes = map[string]string{"activity": "charge_card", "amount": "999999"}

	if _, err := daprhistory.VerifyChain(tampered, sigs, certs, daprhistory.VerifyOptions{}); err == nil {
		t.Fatal("VerifyChain: expected an error for a tampered event, got nil")
	}
}

func TestVerifyChain_TamperedSignatureFails(t *testing.T) {
	signer := mustSigner(t, 0, "example.org", "default", "order-agent")
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-4", "BookVenue", start, daprhistory.EventExecutionCompleted)

	sigs, err := testfixture.SignChain(events, []testfixture.Batch{{From: 0, To: 3, Signer: signer}})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}
	certs := []daprhistory.CertEntry{signer.CertEntry(false)}

	tampered := append([]daprhistory.HistorySignature(nil), sigs...)
	badSig := append([]byte(nil), tampered[0].Signature...)
	badSig[0] ^= 0xFF
	tampered[0].Signature = badSig

	if _, err := daprhistory.VerifyChain(events, tampered, certs, daprhistory.VerifyOptions{}); err == nil {
		t.Fatal("VerifyChain: expected an error for a tampered signature, got nil")
	}
}

func TestVerifyChain_BrokenBatchCoverageRefuses(t *testing.T) {
	signer := mustSigner(t, 0, "example.org", "default", "order-agent")
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-5", "BookVenue", start, daprhistory.EventExecutionCompleted)

	// Deliberately leave a gap: covers events 0..1 and 3..3, skipping event 2.
	sigs, err := testfixture.SignChain(events, []testfixture.Batch{
		{From: 0, To: 1, Signer: signer},
		{From: 3, To: 3, Signer: signer},
	})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}
	certs := []daprhistory.CertEntry{signer.CertEntry(false)}

	if _, err := daprhistory.VerifyChain(events, sigs, certs, daprhistory.VerifyOptions{}); err == nil {
		t.Fatal("VerifyChain: expected an error for a gap in batch coverage, got nil")
	}
}

func TestVerifyChain_UnsupportedAlgorithmRejected(t *testing.T) {
	signer := mustSigner(t, 0, "example.org", "default", "order-agent")
	start := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-instance-6", "BookVenue", start, daprhistory.EventExecutionCompleted)

	sigs, err := testfixture.SignChain(events, []testfixture.Batch{{From: 0, To: 3, Signer: signer}})
	if err != nil {
		t.Fatalf("SignChain: %v", err)
	}
	sigs[0].Algorithm = daprhistory.AlgorithmRSA
	certs := []daprhistory.CertEntry{signer.CertEntry(false)}

	if _, err := daprhistory.VerifyChain(events, sigs, certs, daprhistory.VerifyOptions{}); err == nil {
		t.Fatal("VerifyChain: expected an error for an unsupported algorithm, got nil")
	}
}
