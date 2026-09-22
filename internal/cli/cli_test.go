package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/A-TURBO-99/vt/internal/vtapi"
)

func writeConfig(t *testing.T, primary, fallback string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"api_key_1":"` + primary + `","api_key_2":"` + fallback + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunExtractsURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"response_code": 1,
			"detected_urls": [{"url": "https://example.com/page"}],
			"undetected_urls": [["https://example.com/", "h", 0, 90, "2026-01-01 00:00:00"]],
			"subdomains": ["api.example.com"]
		}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}

	cfg := writeConfig(t, "k1", "")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if strings.Contains(out, "[+]") || strings.Contains(out, "VT") || strings.Contains(out, "Author") {
		t.Fatalf("stdout contaminated: %q", out)
	}
	if !strings.Contains(stderr.String(), "[+] Processing: example.com") {
		t.Fatalf("missing status: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Author: A-TURBO-99") {
		t.Fatalf("missing banner: %s", stderr.String())
	}

	lines := splitLines(out)
	if len(lines) != 2 {
		t.Fatalf("lines=%v", lines)
	}
	if lines[0] != "https://example.com/page" || lines[1] != "https://example.com/" {
		t.Fatalf("lines=%v", lines)
	}
}

func TestFallbackAPIKey(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		key := r.URL.Query().Get("apikey")
		if key == "primary-bad" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"response_code":-1,"verbose_msg":"Invalid key"}`)
			return
		}
		if key != "fallback-good" {
			t.Errorf("unexpected key")
		}
		io.WriteString(w, `{"response_code":1,"subdomains":["ok.example.com"]}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "primary-bad", "fallback-good")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-s", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "ok.example.com\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
	if strings.Contains(stderr.String(), "primary-bad") || strings.Contains(stderr.String(), "fallback-good") {
		t.Fatalf("api keys leaked: %s", stderr.String())
	}
}

func TestGlobalDedupAndOutputFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		switch domain {
		case "a.com":
			io.WriteString(w, `{"response_code":1,"detected_urls":[{"url":"https://shared.example/"},{"url":"https://a.example/"}]}`)
		case "b.com":
			io.WriteString(w, `{"response_code":1,"detected_urls":[{"url":"https://shared.example/"},{"url":"https://b.example/"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "urls.txt")

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1", "")
	code := app.Run(context.Background(), []string{"-l", list, "-u", "-o", outFile, "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}

	got := splitLines(stdout.String())
	want := []string{"https://shared.example/", "https://a.example/", "https://b.example/"}
	if len(got) != len(want) {
		t.Fatalf("stdout lines=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stdout lines=%v", got)
		}
	}

	saved, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != stdout.String() {
		t.Fatalf("file=%q stdout=%q", saved, stdout.String())
	}
}

func TestConflictingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-s"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty")
	}
}

func TestMissingMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-h"})
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("help should not write stdout")
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestAllModeBlankLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{
			"response_code": 1,
			"detected_urls": [{"url": "https://example.com/"}],
			"subdomains": ["api.example.com"]
		}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1", "")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-a", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "https://example.com/\n\napi.example.com\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
