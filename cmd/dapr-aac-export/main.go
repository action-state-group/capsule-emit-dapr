// SPDX-License-Identifier: Apache-2.0
//
// Command dapr-aac-export reads a directory of state-store-shaped fixture
// files (see README for the exact file naming/format) representing one
// signed Dapr 1.18 workflow history, verifies the signature chain, projects
// it into an Agent Action Capsule, and prints the capsule as JSON on
// stdout.
//
// This CLI reads synthetic fixture files, never a live Dapr state store —
// see the repository README's LIMITATIONS section.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/action-state-group/dapr-aac-export/aacexport"
	"github.com/action-state-group/dapr-aac-export/anchor"
	"github.com/action-state-group/dapr-aac-export/daprhistory"
)

func main() {
	dir := flag.String("dir", "", "directory of state-store-shaped fixture files (required)")
	operator := flag.String("operator", "", "override the operator field instead of using the SPIFFE trust domain")
	doAnchor := flag.Bool("anchor", false, "attempt to anchor the resulting capsule_id (non-fatal on failure)")
	anchorURL := flag.String("anchor-url", anchor.DefaultURL, "anchor service URL")
	anchorTimeout := flag.Duration("anchor-timeout", anchor.DefaultTimeout, "timeout spanning the anchor fetch and body read")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: -dir is required")
		flag.Usage()
		os.Exit(2)
	}

	events, sigs, certs, err := loadFixtures(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading fixtures from %s: %v\n", *dir, err)
		os.Exit(1)
	}

	capsule, capsuleID, err := aacexport.FromSignedHistory(
		events, sigs, certs,
		daprhistory.VerifyOptions{}, // no trust-root pool wired into the CLI yet; see README
		aacexport.Config{OperatorOverride: *operator},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(capsule, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: encoding capsule JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	if *doAnchor {
		ctx, cancel := context.WithTimeout(context.Background(), *anchorTimeout+time.Second)
		defer cancel()
		res := anchor.Anchor(ctx, capsuleID, anchor.Config{URL: *anchorURL, Timeout: *anchorTimeout})
		if res.Anchored {
			fmt.Fprintf(os.Stderr, "anchored: leaf_index=%d tree_size=%d entry_hash=%s\n", res.LeafIndex, res.TreeSize, res.EntryHash)
			fmt.Fprintln(os.Stderr, "note: the printed capsule above is still assurance.attestation_mode=self_attested; "+
				"this PoC does not re-wrap the capsule with the anchor receipt (that is a substrate/COSE-envelope concern, "+
				"out of scope for this projection PoC — see README)")
		} else {
			fmt.Fprintf(os.Stderr, "anchoring failed (capsule remains valid and self_attested): %v\n", res.Err)
		}
	}
}

// loadFixtures reads history-NNNNNN.json, signature-NNNNNN.json,
// sigcert-NNNNNN.json, and ext-sigcert-NNNNNN.json files from dir. Each
// file holds the JSON encoding of the corresponding daprhistory type. This
// file-per-state-store-key layout is this PoC's own fixture convention
// standing in for a real state store; it is not part of Dapr's documented
// format.
func loadFixtures(dir string) ([]daprhistory.HistoryEvent, []daprhistory.HistorySignature, []daprhistory.CertEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}

	var events []daprhistory.HistoryEvent
	var sigs []daprhistory.HistorySignature
	var certs []daprhistory.CertEntry

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading %s: %w", name, err)
		}
		switch {
		case strings.HasPrefix(name, "history-"):
			var ev daprhistory.HistoryEvent
			if err := json.Unmarshal(data, &ev); err != nil {
				return nil, nil, nil, fmt.Errorf("parsing %s: %w", name, err)
			}
			events = append(events, ev)
		case strings.HasPrefix(name, "signature-"):
			var sig daprhistory.HistorySignature
			if err := json.Unmarshal(data, &sig); err != nil {
				return nil, nil, nil, fmt.Errorf("parsing %s: %w", name, err)
			}
			sigs = append(sigs, sig)
		case strings.HasPrefix(name, "ext-sigcert-"), strings.HasPrefix(name, "sigcert-"):
			var cert daprhistory.CertEntry
			if err := json.Unmarshal(data, &cert); err != nil {
				return nil, nil, nil, fmt.Errorf("parsing %s: %w", name, err)
			}
			certs = append(certs, cert)
		default:
			// Ignore files that don't match a known state-store key prefix
			// (e.g. a README inside the fixture directory).
		}
	}

	return events, sigs, certs, nil
}
