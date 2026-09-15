package mcpadapter

import (
	"strings"
	"testing"
)

func TestRenderPreviewEscapesBeforeBounding(t *testing.T) {
	input := []byte(strings.Repeat("\x1b", execPreviewBytes))
	got := renderPreview(input, nil, false, false, execPreviewBytes)
	if len(got.Stdout) > execPreviewBytes {
		t.Fatalf("rendered stdout is %d bytes, limit is %d", len(got.Stdout), execPreviewBytes)
	}
	if strings.ContainsRune(got.Stdout, '\x1b') {
		t.Fatal("raw escape byte survived rendering")
	}
	if !got.StdoutTruncated {
		t.Fatal("expected escaped expansion to be marked truncated")
	}
}

func TestSafeTextEscapesControlAndInvalidUTF8(t *testing.T) {
	got := safeText([]byte{'o', 'k', '\n', 0x1b, '[', '3', '1', 'm', 0xff, '\t'})
	want := "ok\n\\x1b[31m\\xff\t"
	if got != want {
		t.Fatalf("safeText() = %q, want %q", got, want)
	}
}

func TestRenderOutputTotalBoundAndQueryContext(t *testing.T) {
	stdout := []byte(strings.Repeat("A", 9000) + "NEEDLE" + strings.Repeat("B", 9000))
	stderr := []byte(strings.Repeat("E", 18000))
	got := renderOutput(stdout, stderr, false, false, "NEEDLE")
	if len(got.Stdout)+len(got.Stderr) > outputReadBytes {
		t.Fatalf("combined output is %d bytes, limit is %d", len(got.Stdout)+len(got.Stderr), outputReadBytes)
	}
	if !strings.Contains(got.Stdout, "NEEDLE") {
		t.Fatal("query-centered stdout omitted the query")
	}
	if !got.StdoutTruncated || !got.StderrTruncated {
		t.Fatal("expected both streams to be marked truncated")
	}
}

func TestHeadTailKeepsUTF8Valid(t *testing.T) {
	text := strings.Repeat("猫", 100)
	got, truncated := headTail(text, 101)
	if !truncated {
		t.Fatal("expected truncation")
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Fatal("truncation split a UTF-8 rune")
	}
}
