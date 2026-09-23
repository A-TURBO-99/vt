package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/A-TURBO-99/vt/internal/vtapi"
)

func writeConfig(t *testing.T, keys ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	fields := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		val := ""
		if i < len(keys) {
			val = keys[i]
		}
		fields = append(fields, fmt.Sprintf(`"api_key_%d":"%s"`, i+1, val))
	}
	body := "{" + strings.Join(fields, ",") + "}"
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

func TestQuotaRotatesThroughKeys(t *testing.T) {
	var mu sync.Mutex
	var used []string
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("apikey")
		domain := r.URL.Query().Get("domain")
		mu.Lock()
		used = append(used, key)
		counts[key]++
		n := counts[key]
		mu.Unlock()

		switch key {
		case "k1":
			if n >= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		case "k2":
			if n >= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		case "k3":
		default:
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, `{"response_code":1,"subdomains":["`+domain+`.ok"]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\nc.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1", "k2", "k3", "k4", "k5")
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "1", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}

	got := splitLines(stdout.String())
	if len(got) != 3 {
		t.Fatalf("lines=%v stderr=%s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "API rate limit or quota exceeded") {
		t.Fatalf("missing quota message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Switching to the next API key") {
		t.Fatalf("missing switch message: %s", stderr.String())
	}
	for _, key := range []string{"k1", "k2", "k3", "k4", "k5"} {
		if strings.Contains(stderr.String(), key) || strings.Contains(stdout.String(), key) {
			t.Fatalf("api key leaked: %s", key)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(used) < 3 {
		t.Fatalf("used=%v", used)
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

func TestParseDelay(t *testing.T) {
	opt, err := Parse([]string{"-d", "example.com", "-u", "-dl", "0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !opt.DelaySet || opt.Delay != 0.5 {
		t.Fatalf("delay=%v set=%v", opt.Delay, opt.DelaySet)
	}

	def, err := Parse([]string{"-d", "example.com", "-u"})
	if err != nil {
		t.Fatal(err)
	}
	if def.DelaySet {
		t.Fatal("delay should not be marked as set")
	}
}

func TestInvalidDelay(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-dl", "-1"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestDelayAppliedBetweenRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"response_code":1,"subdomains":["ok"]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\nc.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	start := time.Now()
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "1", "-dl", "0.05", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("delay not applied, elapsed=%s", elapsed)
	}
}

func TestDefaultDelayUsedWhenFlagAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"response_code":1,"subdomains":["ok"]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout:       &stdout,
		Stderr:       &stderr,
		Client:       vtapi.NewWithOptions(srv.URL, srv.Client()),
		DefaultDelay: 50 * time.Millisecond,
	}
	cfg := writeConfig(t, "k1")
	start := time.Now()
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "1", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("default delay not applied, elapsed=%s", elapsed)
	}
}

func TestInvalidThreads(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-t", "0"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestParseDefaultThreads(t *testing.T) {
	opt, err := Parse([]string{"-d", "example.com", "-u"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Threads != 1 {
		t.Fatalf("threads=%d", opt.Threads)
	}
}

func TestThreadsProcessAll(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		domain := r.URL.Query().Get("domain")
		io.WriteString(w, `{"response_code":1,"subdomains":["`+domain+`.ok"]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\nc.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1", "")
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "3", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() != 3 {
		t.Fatalf("hits=%d", hits.Load())
	}
	got := splitLines(stdout.String())
	want := map[string]bool{"a.com.ok": true, "b.com.ok": true, "c.com.ok": true}
	if len(got) != 3 {
		t.Fatalf("lines=%v", got)
	}
	for _, line := range got {
		if !want[line] {
			t.Fatalf("unexpected %q in %v", line, got)
		}
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
