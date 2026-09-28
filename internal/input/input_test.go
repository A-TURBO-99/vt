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

func TestIsIPv4(t *testing.T) {
	t.Parallel()

	valid := []string{"8.8.8.8", "1.1.1.1", "192.168.1.1", "  127.0.0.1  ", "0.0.0.0", "255.255.255.255"}
	for _, v := range valid {
		if !IsIPv4(v) {
			t.Fatalf("expected IPv4: %q", v)
		}
	}

	invalid := []string{
		"",
		"example.com",
		"api.example.com",
		"8.8.8",
		"256.1.1.1",
		"1.2.3.4.5",
		"::1",
		"2001:db8::1",
		"::ffff:8.8.8.8",
		"not.an.ip",
		"8.8.8.8.com",
	}
	for _, v := range invalid {
		if IsIPv4(v) {
			t.Fatalf("did not expect IPv4: %q", v)
		}
	}
}

func TestLoadFileMixed(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "example.com\n\n8.8.8.8\n  api.example.com  \n# comment\n1.1.1.1\nfacebook.com\n192.168.1.1\nexample.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := LoadTargets("", path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "8.8.8.8", "api.example.com", "1.1.1.1", "facebook.com", "192.168.1.1"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
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
