package banner

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBannerAlignment(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	Print(&buf)
	text := buf.String()
	if !strings.Contains(text, "VT") {
		t.Fatalf("missing VT:\n%s", text)
	}
	if !strings.Contains(text, "Author: A-TURBO-99") {
		t.Fatalf("missing author:\n%s", text)
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	width := utf8.RuneCountInString(lines[0])
	for i, line := range lines {
		if utf8.RuneCountInString(line) != width {
			t.Fatalf("line %d width %d want %d: %q", i, utf8.RuneCountInString(line), width, line)
		}
	}
}
