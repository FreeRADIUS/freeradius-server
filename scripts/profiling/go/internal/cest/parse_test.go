package cest

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// nonSeeker hides bytes.Reader's Seek so ReadSummaryIr takes the full-scan path.
type nonSeeker struct{ io.Reader }

// TestReadSummaryIr covers the tail-seek fast path (seekable, summary in trailer),
// the non-seekable full-scan path, and the fallback when the summary sits outside
// the tail window of a seekable stream.
func TestReadSummaryIr(t *testing.T) {
	trailer := "fn=main\n0 100\nsummary: 4242\ntotals: 4242\n"

	// Seekable, small file: summary found in the tail scan.
	if ir := ReadSummaryIr(bytes.NewReader([]byte("events: Ir\n" + trailer))); ir != 4242 {
		t.Errorf("seekable small = %d; want 4242", ir)
	}

	// Non-seekable stream: same content, full-scan path.
	if ir := ReadSummaryIr(nonSeeker{strings.NewReader("events: Ir\n" + trailer)}); ir != 4242 {
		t.Errorf("non-seekable = %d; want 4242", ir)
	}

	// Seekable, summary BEFORE a >window body: tail scan misses, full-scan finds.
	big := "events: Ir\nsummary: 777\n" + strings.Repeat("fn=f\n1 2\n", 60000) // > summaryTailWindow
	if int64(len(big)) <= summaryTailWindow {
		t.Fatalf("test body %d not larger than tail window %d", len(big), summaryTailWindow)
	}
	if ir := ReadSummaryIr(bytes.NewReader([]byte(big))); ir != 777 {
		t.Errorf("seekable summary-before-body = %d; want 777 (fallback full scan)", ir)
	}
}
