// SPDX-License-Identifier: Apache-2.0
//
// Command gen-example-fixtures (re)generates the synthetic fixture
// directories under examples/ that the README's "how to run" walkthrough
// points at. It is a developer tool, not part of the adapter: it exists so
// the example fixtures can be regenerated (e.g. after a HistoryEvent/
// HistorySignature shape change) instead of hand-maintained.
//
// The certificates and keys it writes are freshly generated on every run
// and are for demonstration only.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/action-state-group/capsule-emit-dapr/daprhistory"
	"github.com/action-state-group/capsule-emit-dapr/internal/testfixture"
)

func main() {
	if err := writeHappyPath(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := writeRotatedCert(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("wrote examples/happy-path and examples/cert-rotation")
}

func writeHappyPath() error {
	signer, err := testfixture.NewSignerCert(0, "example.org", "default", "order-agent")
	if err != nil {
		return err
	}
	start := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-book-venue-20260716-1", "BookVenue", start, daprhistory.EventExecutionCompleted)
	sigs, err := testfixture.SignChain(events, []testfixture.Batch{{From: 0, To: uint64(len(events) - 1), Signer: signer}})
	if err != nil {
		return err
	}
	return writeFixtureDir("examples/happy-path", events, sigs, []daprhistory.CertEntry{signer.CertEntry(false)})
}

func writeRotatedCert() error {
	signerA, err := testfixture.NewSignerCert(0, "example.org", "default", "order-agent")
	if err != nil {
		return err
	}
	signerB, err := testfixture.NewSignerCert(1, "example.org", "default", "order-agent")
	if err != nil {
		return err
	}
	start := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	events := testfixture.SimpleHistory("wf-book-venue-20260716-2", "BookVenue", start, daprhistory.EventExecutionCompleted)
	sigs, err := testfixture.SignChain(events, []testfixture.Batch{
		{From: 0, To: 1, Signer: signerA},
		{From: 2, To: 3, Signer: signerB},
	})
	if err != nil {
		return err
	}
	return writeFixtureDir("examples/cert-rotation", events, sigs,
		[]daprhistory.CertEntry{signerA.CertEntry(false), signerB.CertEntry(false)})
}

func writeFixtureDir(dir string, events []daprhistory.HistoryEvent, sigs []daprhistory.HistorySignature, certs []daprhistory.CertEntry) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, e := range events {
		if err := writeJSON(filepath.Join(dir, fmt.Sprintf("history-%06d.json", e.Index)), e); err != nil {
			return err
		}
	}
	for _, s := range sigs {
		if err := writeJSON(filepath.Join(dir, fmt.Sprintf("signature-%06d.json", s.Index)), s); err != nil {
			return err
		}
	}
	for _, c := range certs {
		name := fmt.Sprintf("sigcert-%06d.json", c.Index)
		if c.Foreign {
			name = fmt.Sprintf("ext-sigcert-%06d.json", c.Index)
		}
		if err := writeJSON(filepath.Join(dir, name), c); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
