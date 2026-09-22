package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSingleDomain(t *testing.T) {
	t.Parallel()

	got, err := LoadTargets(" example.com ", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("got %v", got)
	}
}

func TestLoadFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "domains.txt")
	content := "example.com\n\n  example.org  \n# comment\nexample.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LoadTargets("", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "example.com" || got[1] != "example.org" {
		t.Fatalf("got %v", got)
	}
}

func TestLoadValidation(t *testing.T) {
	t.Parallel()

	if _, err := LoadTargets("", ""); err == nil {
		t.Fatal("expected missing target error")
	}
	if _, err := LoadTargets("a.com", "file.txt"); err == nil {
		t.Fatal("expected both flags error")
	}
	if _, err := LoadTargets("", filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected missing file error")
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("\n  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets("", empty); err == nil {
		t.Fatal("expected empty file error")
	}
}
