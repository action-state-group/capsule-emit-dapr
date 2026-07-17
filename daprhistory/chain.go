// SPDX-License-Identifier: Apache-2.0
package daprhistory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// ChainResult is the outcome of a successfully verified history chain.
// VerifyChain never returns a partially-valid ChainResult: either every
// event is covered by exactly one verified signature link, or VerifyChain
// returns a nil result and a non-nil error.
type ChainResult struct {
	// ChainHeadDigest is SHA-256 of the final (highest-index) verified
	// HistorySignature's Signature bytes -- the value this adapter treats
	// as "the final signature-chain head digest" (see the judgment call
	// documented on HistorySignature.PrevSignatureDigest and in the
	// project README).
	ChainHeadDigest [32]byte

	EventCount     int
	SignatureCount int
	CertCount      int

	// InstanceID is the workflow instance ID, required to be identical
	// (or absent) across every event in the history.
	InstanceID string

	// WorkflowName is taken from the ExecutionStarted event's Name field,
	// if present.
	WorkflowName string

	// SPIFFEID is the URI SAN of the certificate referenced by the LAST
	// (highest-index) signature -- i.e. the signing identity current at
	// the end of the history, which is what the AAC mapping uses for
	// `developer`. Certificate rotation mid-chain is handled: each
	// signature is verified against the cert its own CertIndex names, so
	// an earlier signature by a rotated-out cert still verifies.
	SPIFFEID string

	// TrustDomain is the SPIFFE trust domain component of SPIFFEID
	// (the host of the spiffe:// URI).
	TrustDomain string

	LastEventType string
	LastEventTime time.Time
}

// VerifyOptions configures VerifyChain.
type VerifyOptions struct {
	// TrustRoots, if non-nil, is used to verify that every referenced
	// certificate chains to a trusted root (standing in for "certs must
	// chain to the Sentry CA trust bundle" in the Dapr docs). If nil,
	// this PoC skips chain-of-trust validation entirely and
	// VerifyChain relies only on the signature math -- this is a
	// deliberate scope reduction, called out prominently in the README,
	// not a claim that root validation is unnecessary.
	TrustRoots *x509.CertPool
}

// chainError is returned by VerifyChain; it identifies which link in the
// chain failed so a caller/log can point at the exact signature or event.
type chainError struct {
	msg string
}

func (e *chainError) Error() string { return e.msg }

func chainErrf(format string, args ...interface{}) error {
	return &chainError{msg: fmt.Sprintf(format, args...)}
}

// VerifyChain recomputes eventsDigest for each signature's declared batch,
// walks the hash chain exactly as documented (signing input =
// SHA-256(previousSignatureDigest || eventsDigest)), and verifies each
// Ed25519 signature against the certificate its signature references —
// handling certificate rotation by looking up the cert per-signature
// rather than once for the whole chain.
//
// VerifyChain never panics; all failure modes are returned as errors.
func VerifyChain(events []HistoryEvent, sigs []HistorySignature, certs []CertEntry, opts VerifyOptions) (*ChainResult, error) {
	if len(events) == 0 {
		return nil, chainErrf("no history events supplied")
	}
	if len(sigs) == 0 {
		return nil, chainErrf("no history signatures supplied; an unsigned history cannot be verified")
	}

	sortedEvents := append([]HistoryEvent(nil), events...)
	sort.Slice(sortedEvents, func(i, j int) bool { return sortedEvents[i].Index < sortedEvents[j].Index })
	for i, e := range sortedEvents {
		if e.Index != uint64(i) {
			return nil, chainErrf("history events are not contiguous starting at 0: event at position %d has index %d", i, e.Index)
		}
	}

	instanceID, err := consistentInstanceID(sortedEvents)
	if err != nil {
		return nil, err
	}
	workflowName := workflowNameOf(sortedEvents)

	certTable := make(map[uint64]CertEntry, len(certs))
	for _, c := range certs {
		if _, dup := certTable[c.Index]; dup {
			return nil, chainErrf("duplicate certificate table index %d", c.Index)
		}
		certTable[c.Index] = c
	}

	sortedSigs := append([]HistorySignature(nil), sigs...)
	sort.Slice(sortedSigs, func(i, j int) bool { return sortedSigs[i].Index < sortedSigs[j].Index })
	for i, s := range sortedSigs {
		if s.Index != uint64(i) {
			return nil, chainErrf("history signatures are not contiguous starting at 0: signature at position %d has index %d", i, s.Index)
		}
	}

	// Batch coverage must be a contiguous, gap-free, overlap-free
	// partition of the full event range (documented as "each signature
	// covers a contiguous range of events"; this PoC additionally
	// requires the union of ranges across all signatures to exactly
	// cover every event exactly once, which is the only reading under
	// which "every state load walks the full chain" is a complete
	// verification).
	wantFrom := sortedEvents[0].Index
	for i, s := range sortedSigs {
		if s.FromEventIndex != wantFrom {
			return nil, chainErrf("signature %d covers events starting at %d, expected %d (gap or overlap in batch coverage)", i, s.FromEventIndex, wantFrom)
		}
		if s.ToEventIndex < s.FromEventIndex {
			return nil, chainErrf("signature %d has to_event_index %d < from_event_index %d", i, s.ToEventIndex, s.FromEventIndex)
		}
		wantFrom = s.ToEventIndex + 1
	}
	lastEventIndex := sortedEvents[len(sortedEvents)-1].Index
	if wantFrom != lastEventIndex+1 {
		return nil, chainErrf("signature batches cover events up to %d, but history has events up to %d", wantFrom-1, lastEventIndex)
	}

	var prevSigDigest []byte // empty for the first signature, per the documented judgment call
	var lastCert CertEntry
	for i, s := range sortedSigs {
		batch := sortedEvents[s.FromEventIndex : s.ToEventIndex+1]
		eventsDigest, err := ComputeEventsDigest(batch)
		if err != nil {
			return nil, chainErrf("signature %d: computing eventsDigest: %v", i, err)
		}

		signingInput := SigningInput(prevSigDigest, eventsDigest)

		if s.Algorithm != AlgorithmEd25519 {
			return nil, chainErrf("signature %d: algorithm %q is not implemented by this PoC (Ed25519 only; see README)", i, s.Algorithm)
		}

		cert, ok := certTable[s.CertIndex]
		if !ok {
			return nil, chainErrf("signature %d: no certificate at table index %d", i, s.CertIndex)
		}
		parsed, err := x509.ParseCertificate(cert.DER)
		if err != nil {
			return nil, chainErrf("signature %d: parsing certificate at index %d: %v", i, s.CertIndex, err)
		}
		pub, ok := parsed.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, chainErrf("signature %d: certificate at index %d does not carry an Ed25519 public key", i, s.CertIndex)
		}
		if !ed25519.Verify(pub, signingInput[:], s.Signature) {
			return nil, chainErrf("signature %d (events %d..%d): Ed25519 verification failed against certificate index %d — chain is broken", i, s.FromEventIndex, s.ToEventIndex, s.CertIndex)
		}

		if opts.TrustRoots != nil {
			if _, err := parsed.Verify(x509.VerifyOptions{
				Roots:     opts.TrustRoots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				return nil, chainErrf("signature %d: certificate at index %d does not chain to a trusted root: %v", i, s.CertIndex, err)
			}
		}

		prevSigDigest = SignatureDigest(s.Signature)
		lastCert = cert
	}

	spiffeID, trustDomain, err := spiffeIdentity(lastCert)
	if err != nil {
		return nil, chainErrf("extracting SPIFFE identity from the final signing certificate: %v", err)
	}

	last := sortedEvents[len(sortedEvents)-1]

	var head [32]byte
	copy(head[:], prevSigDigest)

	return &ChainResult{
		ChainHeadDigest: head,
		EventCount:      len(sortedEvents),
		SignatureCount:  len(sortedSigs),
		CertCount:       len(certs),
		InstanceID:      instanceID,
		WorkflowName:    workflowName,
		SPIFFEID:        spiffeID,
		TrustDomain:     trustDomain,
		LastEventType:   last.EventType,
		LastEventTime:   last.Timestamp,
	}, nil
}

// ComputeEventsDigest is SHA-256 over the batch of marshaled events, each
// event length-prefixed with a big-endian uint64, exactly as documented.
// It is exported so fixture builders and tests can construct a
// HistorySignature.Signature over the same signing input VerifyChain
// recomputes, without duplicating the digest algorithm.
func ComputeEventsDigest(batch []HistoryEvent) ([32]byte, error) {
	h := sha256.New()
	for _, e := range batch {
		b, err := e.Marshal()
		if err != nil {
			return [32]byte{}, fmt.Errorf("marshaling event %d: %w", e.Index, err)
		}
		var lenPrefix [8]byte
		binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(b)))
		h.Write(lenPrefix[:])
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SigningInput computes SHA-256(previousSignatureDigest || eventsDigest),
// exactly as documented. It is exported alongside ComputeEventsDigest and
// SignatureDigest so a fixture builder can produce a HistorySignature.Signature
// using the identical construction VerifyChain checks against.
func SigningInput(prevSignatureDigest []byte, eventsDigest [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte(nil), prevSignatureDigest...), eventsDigest[:]...))
}

// SignatureDigest is SHA-256 of raw signature bytes -- this PoC's judgment
// call for what "the previous signature's digest" (HistorySignature.PrevSignatureDigest)
// digests. See the HistorySignature doc comment for why this is a judgment
// call rather than a documented fact.
func SignatureDigest(signature []byte) []byte {
	h := sha256.Sum256(signature)
	return h[:]
}

func consistentInstanceID(events []HistoryEvent) (string, error) {
	var id string
	for _, e := range events {
		if e.InstanceID == "" {
			continue
		}
		if id == "" {
			id = e.InstanceID
			continue
		}
		if e.InstanceID != id {
			return "", chainErrf("inconsistent workflow instance ID across history: %q vs %q", id, e.InstanceID)
		}
	}
	if id == "" {
		return "", chainErrf("no event in the history carries a workflow instance_id")
	}
	return id, nil
}

func workflowNameOf(events []HistoryEvent) string {
	for _, e := range events {
		if e.EventType == EventExecutionStarted && e.Name != "" {
			return e.Name
		}
	}
	return ""
}

// spiffeIdentity extracts the spiffe://<trust-domain>/... URI SAN from a
// certificate and returns (full SPIFFE ID, trust domain).
func spiffeIdentity(cert CertEntry) (string, string, error) {
	parsed, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		return "", "", fmt.Errorf("parsing certificate: %w", err)
	}
	for _, u := range parsed.URIs {
		if u.Scheme == "spiffe" {
			return u.String(), u.Host, nil
		}
	}
	return "", "", fmt.Errorf("no spiffe:// URI SAN present on certificate")
}
