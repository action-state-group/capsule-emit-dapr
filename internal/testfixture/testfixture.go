// SPDX-License-Identifier: Apache-2.0
//
// Package testfixture builds synthetic Dapr-history-shaped fixtures for
// tests: real Ed25519 keys, real self-signed X.509 certs carrying a SPIFFE
// URI SAN, and a correctly hash-chained series of daprhistory.HistorySignature
// values built with the exact same primitives (daprhistory.ComputeEventsDigest,
// daprhistory.SigningInput, daprhistory.SignatureDigest) that
// daprhistory.VerifyChain checks against. It exists only for tests in this
// module; it is not part of the exported adapter surface.
package testfixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/action-state-group/capsule-emit-dapr/daprhistory"
)

// SignerCert is a synthetic signing identity: an Ed25519 keypair and a
// self-signed X.509 certificate carrying a spiffe:// URI SAN, the same
// shape as a Sentry-issued SPIFFE X.509 SVID.
type SignerCert struct {
	Index    uint64
	SPIFFEID string
	Priv     ed25519.PrivateKey
	Pub      ed25519.PublicKey
	DER      []byte
}

// NewSignerCert generates a fresh Ed25519 keypair and a self-signed
// certificate whose URI SAN is spiffe://<trustDomain>/ns/<namespace>/<appID>,
// matching the Dapr docs' description of the SVID identity.
func NewSignerCert(index uint64, trustDomain, namespace, appID string) (*SignerCert, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	spiffeID := fmt.Sprintf("spiffe://%s/ns/%s/%s", trustDomain, namespace, appID)
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parsing SPIFFE URI: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: appID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("creating self-signed certificate: %w", err)
	}

	return &SignerCert{Index: index, SPIFFEID: spiffeID, Priv: priv, Pub: pub, DER: der}, nil
}

// CertEntry returns the daprhistory.CertEntry state-store shape for this
// signer.
func (s *SignerCert) CertEntry(foreign bool) daprhistory.CertEntry {
	return daprhistory.CertEntry{Index: s.Index, Foreign: foreign, DER: s.DER}
}

// SimpleHistory returns a small, realistic-shaped Dapr workflow history:
// ExecutionStarted, one TaskCompleted, and (if completed) a terminal event.
// terminalType should be daprhistory.EventExecutionCompleted,
// EventExecutionFailed, EventExecutionTerminated, or "" to leave the
// workflow without a terminal event (still running).
func SimpleHistory(instanceID, workflowName string, start time.Time, terminalType string) []daprhistory.HistoryEvent {
	events := []daprhistory.HistoryEvent{
		{
			Index:      0,
			EventType:  daprhistory.EventExecutionStarted,
			Timestamp:  start,
			InstanceID: instanceID,
			Name:       workflowName,
		},
		{
			Index:      1,
			EventType:  "TaskScheduled",
			Timestamp:  start.Add(1 * time.Second),
			InstanceID: instanceID,
			Attributes: map[string]string{"activity": "charge_card"},
		},
		{
			Index:      2,
			EventType:  "TaskCompleted",
			Timestamp:  start.Add(2 * time.Second),
			InstanceID: instanceID,
			Attributes: map[string]string{"activity": "charge_card", "result": "ok"},
		},
	}
	if terminalType != "" {
		events = append(events, daprhistory.HistoryEvent{
			Index:      3,
			EventType:  terminalType,
			Timestamp:  start.Add(3 * time.Second),
			InstanceID: instanceID,
		})
	}
	return events
}

// Batch names one signature's event coverage and signer.
type Batch struct {
	From, To uint64
	Signer   *SignerCert
}

// SignChain builds a correctly hash-chained series of HistorySignature
// values covering events using the given batches, in order. Each batch may
// use a different Signer, which is exactly how certificate rotation
// mid-chain is exercised in tests.
func SignChain(events []daprhistory.HistoryEvent, batches []Batch) ([]daprhistory.HistorySignature, error) {
	var sigs []daprhistory.HistorySignature
	var prevDigest []byte

	for i, b := range batches {
		batchEvents := eventsInRange(events, b.From, b.To)
		eventsDigest, err := daprhistory.ComputeEventsDigest(batchEvents)
		if err != nil {
			return nil, fmt.Errorf("batch %d: computing eventsDigest: %w", i, err)
		}
		signingInput := daprhistory.SigningInput(prevDigest, eventsDigest)
		sig := ed25519.Sign(b.Signer.Priv, signingInput[:])

		sigs = append(sigs, daprhistory.HistorySignature{
			Index:               uint64(i),
			FromEventIndex:      b.From,
			ToEventIndex:        b.To,
			CertIndex:           b.Signer.Index,
			Algorithm:           daprhistory.AlgorithmEd25519,
			PrevSignatureDigest: append([]byte(nil), prevDigest...),
			Signature:           sig,
		})

		prevDigest = daprhistory.SignatureDigest(sig)
	}
	return sigs, nil
}

func eventsInRange(events []daprhistory.HistoryEvent, from, to uint64) []daprhistory.HistoryEvent {
	var out []daprhistory.HistoryEvent
	for _, e := range events {
		if e.Index >= from && e.Index <= to {
			out = append(out, e)
		}
	}
	return out
}
