// SPDX-License-Identifier: Apache-2.0
//
// Package anchor submits a capsule_id to a SCITT-style anchor service
// (POST {"capsule_id": "<64-hex>"} to /v1/digest, matching capsule-anchor's
// simple digest surface) and reports the outcome.
//
// Anchoring failure is always non-fatal: the capsule this PoC exports is a
// complete, valid, self_attested Agent Action Capsule with or without a
// successful anchor call. A caller should log a failed Result and continue
// treating the capsule as self_attested rather than abort the export.
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultURL is the anchor endpoint this PoC targets by default.
const DefaultURL = "https://anchor.agentactioncapsule.org/v1/digest"

// DefaultTimeout bounds both the HTTP round trip and the response body
// read (see Anchor).
const DefaultTimeout = 10 * time.Second

// maxResponseBytes bounds how much of the response body Anchor will ever
// read, regardless of what Content-Length claims or how long the server
// keeps the connection open.
const maxResponseBytes = 64 * 1024

// Config configures Anchor. Every field is optional.
type Config struct {
	// URL overrides DefaultURL.
	URL string

	// Timeout overrides DefaultTimeout. It spans BOTH the HTTP fetch
	// (connect through response headers) and the subsequent response
	// body read: Anchor derives a single context.WithTimeout and uses it
	// for both http.Client.Do and the io.ReadAll of the (limited)
	// response body, so a server that responds promptly but then stalls
	// mid-body cannot hang the caller past Timeout.
	Timeout time.Duration

	// Client overrides the http.Client used to make the request
	// (primarily for tests).
	Client *http.Client
}

// Result reports the outcome of an anchor attempt. Anchored is true only
// when the anchor service accepted the capsule_id and returned a receipt;
// Err is non-nil whenever Anchored is false, and callers should treat a
// non-nil Err as informational, not fatal: the capsule remains a valid,
// self_attested Agent Action Capsule.
type Result struct {
	Anchored bool
	URL      string

	// EntryHash, LeafIndex, TreeSize, ReceiptB64 are populated only when
	// Anchored is true; they mirror capsule-anchor's /v1/digest response
	// shape.
	EntryHash  string
	LeafIndex  int64
	TreeSize   int64
	ReceiptB64 string

	Err error
}

type digestRequest struct {
	CapsuleID string `json:"capsule_id"`
}

type digestResponse struct {
	ReceiptB64 string `json:"receipt_b64"`
	EntryHash  string `json:"entry_hash"`
	LeafIndex  int64  `json:"leaf_index"`
	TreeSize   int64  `json:"tree_size"`
}

// Anchor POSTs capsuleID to the configured anchor endpoint. It never
// returns an error via panic and never blocks longer than cfg.Timeout (or
// DefaultTimeout): the returned Result always has Anchored=false and a
// descriptive Err on any failure — invalid input, network failure,
// timeout, non-200 response, or an unparseable response body.
func Anchor(ctx context.Context, capsuleID string, cfg Config) Result {
	anchorURL := cfg.URL
	if anchorURL == "" {
		anchorURL = DefaultURL
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := json.Marshal(digestRequest{CapsuleID: capsuleID})
	if err != nil {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("encoding anchor request: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anchorURL, bytes.NewReader(body))
	if err != nil {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("building anchor request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("anchoring failed (capsule remains valid and self_attested): %w", err)}
	}
	defer resp.Body.Close()

	// The context deadline set above bounds this read too: once it fires,
	// the underlying transport unblocks any in-flight Read on resp.Body
	// with a context error, so a slow-body server cannot hold this call
	// open past Timeout.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("reading anchor response (capsule remains valid and self_attested): %w", err)}
	}

	if resp.StatusCode != http.StatusOK {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("anchor service returned HTTP %d: %s", resp.StatusCode, truncate(data, 300))}
	}

	var parsed digestResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Result{Anchored: false, URL: anchorURL, Err: fmt.Errorf("parsing anchor response: %w", err)}
	}

	return Result{
		Anchored:   true,
		URL:        anchorURL,
		EntryHash:  parsed.EntryHash,
		LeafIndex:  parsed.LeafIndex,
		TreeSize:   parsed.TreeSize,
		ReceiptB64: parsed.ReceiptB64,
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
