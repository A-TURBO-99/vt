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
	quoted := make([]string, 0, len(keys))
	for _, key := range keys {
		quoted = append(quoted, fmt.Sprintf("%q", key))
	}
	body := `{"api_keys":[` + strings.Join(quoted, ",") + `]}`
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

func TestQuotaRotatesThroughTenKeys(t *testing.T) {
	var mu sync.Mutex
	var used []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("apikey")
		domain := r.URL.Query().Get("domain")
		mu.Lock()
		used = append(used, key)
		mu.Unlock()

		if key != "k10" {
			w.WriteHeader(http.StatusTooManyRequests)
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
	cfg := writeConfig(t, "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10")
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
	for _, key := range []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10"} {
		if strings.Contains(stderr.String(), key) || strings.Contains(stdout.String(), key) {
			t.Fatalf("api key leaked: %s", key)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(used) < 10 {
		t.Fatalf("expected the rotator to reach key 10; used=%v", used)
	}
	for i := 0; i < 10; i++ {
		want := fmt.Sprintf("k%d", i+1)
		if used[i] != want {
			t.Fatalf("key sequence at index %d: got=%q want=%q; used=%v", i, used[i], want, used)
		}
	}
	if used[9] != "k10" {
		t.Fatalf("tenth key was not used: %v", used)
	}
}

func TestQuotaRotationWrapsToFirstKey(t *testing.T) {
	var mu sync.Mutex
	var used []string
	firstKeyHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("apikey")
		mu.Lock()
		used = append(used, key)
		if key == "k1" {
			firstKeyHits++
		}
		firstHit := firstKeyHits == 1
		mu.Unlock()

		if key == "k1" && !firstHit {
			io.WriteString(w, `{"response_code":1,"subdomains":["wrapped.example.com"]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1", "k2")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-s", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := splitLines(stdout.String()); len(got) != 1 || got[0] != "wrapped.example.com" {
		t.Fatalf("stdout=%q", stdout.String())
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"k1", "k2", "k1"}
	if len(used) != len(want) {
		t.Fatalf("used=%v want=%v", used, want)
	}
	for i := range want {
		if used[i] != want[i] {
			t.Fatalf("used=%v want=%v", used, want)
		}
	}
	if !strings.Contains(stderr.String(), "restarting rotation from the first available API key") {
		t.Fatalf("missing wrap message: %s", stderr.String())
	}
}

func TestAllQuotaKeysKeepCyclingUntilContextCancellation(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout:       &stdout,
		Stderr:       &stderr,
		Client:       vtapi.NewWithOptions(srv.URL, srv.Client()),
		DefaultDelay: time.Millisecond,
	}
	cfg := writeConfig(t, "k1", "k2", "k3")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	code := app.Run(ctx, []string{"-d", "example.com", "-s", "-c", cfg})
	if code != 1 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if hits.Load() < 3 {
		t.Fatalf("expected keys to be retried after a full cycle; requests=%d", hits.Load())
	}
	if !strings.Contains(stderr.String(), "interrupted") {
		t.Fatalf("expected context cancellation message, stderr=%s", stderr.String())
	}
}

func TestRejectedAPIKeyIsSkippedPermanently(t *testing.T) {
	var mu sync.Mutex
	var used []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("apikey")
		mu.Lock()
		used = append(used, key)
		mu.Unlock()
		if key == "bad" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"response_code":-1,"verbose_msg":"Invalid key"}`)
			return
		}
		if key == "good" && len(used) >= 3 {
			io.WriteString(w, `{"response_code":1,"subdomains":["ok.example.com"]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "bad", "good")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-s", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"bad", "good", "good"}
	if len(used) != len(want) {
		t.Fatalf("used=%v want=%v", used, want)
	}
	for i := range want {
		if used[i] != want[i] {
			t.Fatalf("used=%v want=%v", used, want)
		}
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

func TestRunExtractsIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") != "8.8.8.8" {
			t.Errorf("ip=%s", r.URL.Query().Get("ip"))
		}
		if r.URL.Query().Get("domain") != "" {
			t.Errorf("unexpected domain query")
		}
		io.WriteString(w, `{
			"response_code": 1,
			"detected_urls": [{"url": "http://forms.kycaid.com/"}],
			"undetected_urls": [["http://kycaid.com/", "h", 0, 90, "2023-08-13 00:34:26"]],
			"resolutions": [
				{"hostname": "admin.kycaid.com"},
				{"hostname": "api.kycaid.com"}
			]
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
	code := app.Run(context.Background(), []string{"-ip", "8.8.8.8", "-s", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "admin.kycaid.com\napi.kycaid.com\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "[+] Processing: 8.8.8.8") {
		t.Fatalf("missing status: %s", stderr.String())
	}
}

func TestMixedFileRoutesEndpoints(t *testing.T) {
	var mu sync.Mutex
	var domains, ips []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		ip := r.URL.Query().Get("ip")
		mu.Lock()
		if domain != "" {
			domains = append(domains, domain)
			io.WriteString(w, `{"response_code":1,"subdomains":["`+domain+`.ok"]}`)
		} else if ip != "" {
			ips = append(ips, ip)
			io.WriteString(w, `{"response_code":1,"resolutions":[{"hostname":"`+ip+`.host"}]}`)
		} else {
			http.Error(w, "missing target", http.StatusBadRequest)
		}
		mu.Unlock()
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "targets.txt")
	content := "example.com\n8.8.8.8\napi.example.com\n1.1.1.1\n"
	if err := os.WriteFile(list, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "1", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}

	got := splitLines(stdout.String())
	want := []string{"example.com.ok", "8.8.8.8.host", "api.example.com.ok", "1.1.1.1.host"}
	if len(got) != len(want) {
		t.Fatalf("lines=%v stderr=%s", got, stderr.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines=%v", got)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(domains) != 2 || len(ips) != 2 {
		t.Fatalf("domains=%v ips=%v", domains, ips)
	}
}

func TestIPOnlyFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") == "" {
			t.Errorf("expected ip query, got %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"response_code":1,"detected_urls":[{"url":"https://`+r.URL.Query().Get("ip")+`/"}]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "ips.txt")
	if err := os.WriteFile(list, []byte("8.8.8.8\n1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	code := app.Run(context.Background(), []string{"-l", list, "-u", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	got := splitLines(stdout.String())
	if len(got) != 2 || got[0] != "https://8.8.8.8/" || got[1] != "https://1.1.1.1/" {
		t.Fatalf("lines=%v", got)
	}
}

func TestInvalidIP(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-ip", "not-an-ip", "-u"})
	if code != 2 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid IPv4 address") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestConflictingDIP(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-ip", "8.8.8.8", "-u"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestParseIP(t *testing.T) {
	opt, err := Parse([]string{"-ip", "8.8.8.8", "-s"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.IP != "8.8.8.8" || opt.Domain != "" {
		t.Fatalf("opt=%+v", opt)
	}
}

func TestRunExtractsIPsFromDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("domain=%s", r.URL.Query().Get("domain"))
		}
		io.WriteString(w, `{
			"response_code": 1,
			"resolutions": [
				{"hostname": "api.example.com", "ip_address": "1.2.3.4"},
				{"hostname": "www.example.com", "ip_address": "1.2.3.4"},
				{"hostname": "mail.example.com", "ip_address": "5.6.7.8"},
				{"hostname": "empty.example.com", "ip_address": ""}
			]
		}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	outFile := filepath.Join(t.TempDir(), "ips.txt")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-ips", "-o", outFile, "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "1.2.3.4\n5.6.7.8\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "[+] Found 2 IPs") {
		t.Fatalf("missing status: %s", stderr.String())
	}
	saved, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != stdout.String() {
		t.Fatalf("file=%q stdout=%q", saved, stdout.String())
	}
}

func TestRunExtractsIPsFromIPInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") != "8.8.8.8" {
			t.Errorf("ip=%s", r.URL.Query().Get("ip"))
		}
		io.WriteString(w, `{
			"response_code": 1,
			"resolutions": [
				{"hostname": "dns.google", "ip_address": "8.8.8.8"},
				{"hostname": "dns.google", "ip_address": "8.8.4.4"}
			]
		}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	code := app.Run(context.Background(), []string{"-ip", "8.8.8.8", "-ips", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "8.8.8.8\n8.8.4.4\n" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestMixedFileExtractsIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		ip := r.URL.Query().Get("ip")
		switch {
		case domain == "example.com":
			io.WriteString(w, `{"response_code":1,"resolutions":[{"hostname":"a.example.com","ip_address":"1.1.1.1"},{"hostname":"b.example.com","ip_address":"2.2.2.2"}]}`)
		case ip == "8.8.8.8":
			io.WriteString(w, `{"response_code":1,"resolutions":[{"hostname":"dns.google","ip_address":"8.8.8.8"}]}`)
		default:
			io.WriteString(w, `{"response_code":1,"resolutions":[]}`)
		}
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte("example.com\n8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	code := app.Run(context.Background(), []string{"-l", list, "-ips", "-t", "1", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	got := splitLines(stdout.String())
	want := []string{"1.1.1.1", "2.2.2.2", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("lines=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lines=%v", got)
		}
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

func TestConflictingIPSFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-ips"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestAllFlagRemoved(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-a"})
	if code != 2 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
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

func TestParseTimeout(t *testing.T) {
	opt, err := Parse([]string{"-d", "example.com", "-u", "-tm", "10"})
	if err != nil {
		t.Fatal(err)
	}
	if !opt.TimeoutSet || opt.Timeout != 10 {
		t.Fatalf("timeout=%v set=%v", opt.Timeout, opt.TimeoutSet)
	}

	def, err := Parse([]string{"-d", "example.com", "-u"})
	if err != nil {
		t.Fatal(err)
	}
	if def.TimeoutSet {
		t.Fatal("timeout should not be marked as set")
	}
	if def.Timeout != 6 {
		t.Fatalf("default timeout=%v", def.Timeout)
	}
}

func TestInvalidTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := &App{Stdout: &stdout, Stderr: &stderr}
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-tm", "0"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
	code = app.Run(context.Background(), []string{"-d", "example.com", "-u", "-tm", "-1"})
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestTimeoutCancelsSlowRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, `{"response_code":1,"detected_urls":[{"url":"https://example.com/"}]}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout:         &stdout,
		Stderr:         &stderr,
		Client:         vtapi.NewWithOptions(srv.URL, srv.Client()),
		DefaultTimeout: 6 * time.Second,
	}
	cfg := writeConfig(t, "k1")
	start := time.Now()
	code := app.Run(context.Background(), []string{"-d", "example.com", "-u", "-tm", "0.05", "-c", cfg})
	elapsed := time.Since(start)
	if code == 0 {
		t.Fatalf("expected timeout failure, stdout=%q", stdout.String())
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("timeout not applied, elapsed=%s", elapsed)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestTimeoutAppliesToIPRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, `{"response_code":1,"resolutions":[{"hostname":"dns.google"}]}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout: &stdout,
		Stderr: &stderr,
		Client: vtapi.NewWithOptions(srv.URL, srv.Client()),
	}
	cfg := writeConfig(t, "k1")
	start := time.Now()
	code := app.Run(context.Background(), []string{"-ip", "8.8.8.8", "-s", "-tm", "0.05", "-c", cfg})
	elapsed := time.Since(start)
	if code == 0 {
		t.Fatalf("expected timeout failure")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("timeout not applied, elapsed=%s", elapsed)
	}
}

func TestTimeoutConcurrentRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		io.WriteString(w, `{"response_code":1,"subdomains":["ok"]}`)
	}))
	defer srv.Close()

	list := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(list, []byte("a.com\nb.com\n"), 0o644); err != nil {
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
	code := app.Run(context.Background(), []string{"-l", list, "-s", "-t", "2", "-dl", "0", "-tm", "0.05", "-c", cfg})
	elapsed := time.Since(start)
	if code == 0 {
		t.Fatalf("expected timeout failure")
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("timeout not applied concurrently, elapsed=%s", elapsed)
	}
}

func TestDefaultTimeoutUsedWhenFlagAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"response_code":1,"subdomains":["ok"]}`)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	app := &App{
		Stdout:         &stdout,
		Stderr:         &stderr,
		Client:         vtapi.NewWithOptions(srv.URL, srv.Client()),
		DefaultTimeout: 6 * time.Second,
	}
	cfg := writeConfig(t, "k1")
	code := app.Run(context.Background(), []string{"-d", "example.com", "-s", "-c", cfg})
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "ok\n" {
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
