package output

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteResultsAndFile(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "out.txt")
	w, err := New(&stdout, &stderr, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteResults([]string{"a", "", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "a\nb\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "a\nb\n" {
		t.Fatalf("file=%q", data)
	}
}
