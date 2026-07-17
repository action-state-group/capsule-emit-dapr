// SPDX-License-Identifier: Apache-2.0
package anchor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnchor_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req digestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("server: decoding request: %v", err)
		}
		if req.CapsuleID != "aa11" {
			t.Errorf("server: got capsule_id %q, want aa11", req.CapsuleID)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(digestResponse{
			ReceiptB64: "ZmFrZS1yZWNlaXB0",
			EntryHash:  "deadbeef",
			LeafIndex:  3,
			TreeSize:   4,
		})
	}))
	defer srv.Close()

	res := Anchor(context.Background(), "aa11", Config{URL: srv.URL})
	if !res.Anchored {
		t.Fatalf("Anchor: expected success, got Err=%v", res.Err)
	}
	if res.LeafIndex != 3 || res.TreeSize != 4 || res.EntryHash != "deadbeef" {
		t.Errorf("Anchor: unexpected result %+v", res)
	}
}

func TestAnchor_NonFatalOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"detail":"bad capsule_id"}`))
	}))
	defer srv.Close()

	res := Anchor(context.Background(), "not-hex", Config{URL: srv.URL})
	if res.Anchored {
		t.Fatal("Anchor: expected failure, got success")
	}
	if res.Err == nil {
		t.Fatal("Anchor: expected a non-nil Err on failure")
	}
}

func TestAnchor_TimeoutSpansFetchAndBodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write headers/partial body promptly, then stall well past the
		// configured timeout before finishing the body. A timeout that only
		// bounded the initial fetch (not the body read) would let this test
		// hang for the full stall duration.
		flusher, ok := w.(http.Flusher)
		w.Write([]byte(`{"entry_hash":`))
		if ok {
			flusher.Flush()
		}
		time.Sleep(2 * time.Second)
		w.Write([]byte(`"deadbeef","leaf_index":1,"tree_size":1,"receipt_b64":"x"}`))
	}))
	defer srv.Close()

	start := time.Now()
	res := Anchor(context.Background(), "aa11", Config{URL: srv.URL, Timeout: 200 * time.Millisecond})
	elapsed := time.Since(start)

	if res.Anchored {
		t.Fatal("Anchor: expected failure due to timeout, got success")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Anchor: took %v, expected the timeout (~200ms) to bound the body read, not the server's 2s stall", elapsed)
	}
}

func TestAnchor_ConnectionFailureNonFatal(t *testing.T) {
	res := Anchor(context.Background(), "aa11", Config{URL: "http://127.0.0.1:1", Timeout: 500 * time.Millisecond})
	if res.Anchored {
		t.Fatal("Anchor: expected failure connecting to a closed port")
	}
	if res.Err == nil {
		t.Fatal("Anchor: expected a non-nil Err")
	}
}
