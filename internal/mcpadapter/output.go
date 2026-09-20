package mcpadapter

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	execPreviewBytes  = 8 << 10
	batchPreviewBytes = 2 << 10
	outputReadBytes   = 12 << 10
)

type renderedStreams struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
}

func renderPreview(stdout, stderr []byte, stdoutSourceTruncated, stderrSourceTruncated bool, perStream int) renderedStreams {
	out, outTruncated := boundedSafeText(stdout, perStream)
	errText, errTruncated := boundedSafeText(stderr, perStream)
	return renderedStreams{
		Stdout:          out,
		Stderr:          errText,
		StdoutTruncated: stdoutSourceTruncated || outTruncated,
		StderrTruncated: stderrSourceTruncated || errTruncated,
	}
}

func renderOutput(stdout, stderr []byte, stdoutSourceTruncated, stderrSourceTruncated bool, query string) renderedStreams {
	stdoutText := safeText(stdout)
	stderrText := safeText(stderr)
	query = strings.TrimSpace(query)

	stdoutBudget, stderrBudget := splitBudget(stdoutText, stderrText, outputReadBytes)
	var out, errText string
	var outTruncated, errTruncated bool
	if query != "" {
		out, outTruncated = queryExcerpt(stdoutText, query, stdoutBudget)
		errText, errTruncated = queryExcerpt(stderrText, query, stderrBudget)
	} else {
		out, outTruncated = headTail(stdoutText, stdoutBudget)
		errText, errTruncated = headTail(stderrText, stderrBudget)
	}
	return renderedStreams{
		Stdout:          out,
		Stderr:          errText,
		StdoutTruncated: stdoutSourceTruncated || outTruncated,
		StderrTruncated: stderrSourceTruncated || errTruncated,
	}
}

func splitBudget(stdout, stderr string, total int) (int, int) {
	switch {
	case stdout == "" && stderr == "":
		return 0, 0
	case stderr == "":
		return total, 0
	case stdout == "":
		return 0, total
	default:
		return total / 2, total - total/2
	}
}

func boundedSafeText(data []byte, maxBytes int) (string, bool) {
	return headTail(safeText(data), maxBytes)
}

func safeText(data []byte) string {
	var b strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", data[0])
			data = data[1:]
			continue
		}
		switch r {
		case '\n':
			b.WriteByte('\n')
		case '\t':
			b.WriteByte('\t')
		default:
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				if r <= 0xff {
					fmt.Fprintf(&b, "\\x%02x", r)
				} else if r <= 0xffff {
					fmt.Fprintf(&b, "\\u%04x", r)
				} else {
					fmt.Fprintf(&b, "\\U%08x", r)
				}
			} else {
				b.WriteRune(r)
			}
		}
		data = data[size:]
	}
	return b.String()
}

func headTail(text string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", text != ""
	}
	if len(text) <= maxBytes {
		return text, false
	}
	marker := "\n... output omitted ...\n"
	if len(marker) >= maxBytes {
		return prefixBytes(text, maxBytes), true
	}
	remaining := maxBytes - len(marker)
	headBudget := remaining / 2
	tailBudget := remaining - headBudget
	head := prefixBytes(text, headBudget)
	tail := suffixBytes(text, tailBudget)
	return head + marker + tail, true
}

func queryExcerpt(text, query string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		return "", text != ""
	}
	if len(text) <= maxBytes {
		return text, false
	}
	idx := strings.Index(text, query)
	if idx < 0 {
		return headTail(text, maxBytes)
	}

	markerPrefix := "... earlier output omitted ...\n"
	markerSuffix := "\n... later output omitted ..."
	markerBytes := len(markerPrefix) + len(markerSuffix)
	if markerBytes >= maxBytes {
		return prefixBytes(text[idx:], maxBytes), true
	}
	budget := maxBytes - markerBytes
	beforeBudget := budget / 2
	afterBudget := budget - beforeBudget
	start := byteStart(text, idx, beforeBudget)
	end := byteEnd(text, idx+len(query), afterBudget)

	prefix := ""
	if start > 0 {
		prefix = markerPrefix
	}
	suffix := ""
	if end < len(text) {
		suffix = markerSuffix
	}
	result := prefix + text[start:end] + suffix
	if len(result) > maxBytes {
		result = prefixBytes(result, maxBytes)
	}
	return result, start > 0 || end < len(text)
}

func byteStart(text string, center, budget int) int {
	if budget <= 0 || center <= 0 {
		return center
	}
	start := center - budget
	if start < 0 {
		start = 0
	}
	for start < center && !utf8.RuneStart(text[start]) {
		start++
	}
	return start
}

func byteEnd(text string, center, budget int) int {
	if budget <= 0 || center >= len(text) {
		return center
	}
	end := center + budget
	if end > len(text) {
		end = len(text)
	}
	for end > center && end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	return end
}

func prefixBytes(text string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(text) <= maxBytes {
		return text
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

func suffixBytes(text string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(text) <= maxBytes {
		return text
	}
	start := len(text) - maxBytes
	for start < len(text) && !utf8.RuneStart(text[start]) {
		start++
	}
	return text[start:]
}
