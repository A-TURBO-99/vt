package vtapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apikey") != "k1" {
			t.Errorf("apikey=%s", r.URL.Query().Get("apikey"))
		}
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("domain=%s", r.URL.Query().Get("domain"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"response_code":1,"verbose_msg":"ok","subdomains":["a.example.com"]}`)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	body, err := c.Fetch(context.Background(), "example.com", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "a.example.com") {
		t.Fatalf("body=%s", body)
	}
}

func TestFetchInvalidKey(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"response_code":-1,"verbose_msg":"Invalid key"}`)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	_, err := c.Fetch(context.Background(), "example.com", "bad")
	if !IsKeyError(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestFetchRateLimit(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	_, err := c.Fetch(context.Background(), "example.com", "k1")
	if !IsKeyError(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestFetchQuotaMessage(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"response_code":-1,"verbose_msg":"Quota exceeded"}`)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	_, err := c.Fetch(context.Background(), "example.com", "k1")
	if !IsKeyError(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestFetchDoesNotLeakKey(t *testing.T) {
	t.Parallel()

	c := NewWithOptions("http://127.0.0.1:1", &http.Client{Timeout: 50 * time.Millisecond})
	_, err := c.Fetch(context.Background(), "example.com", "super-secret-key")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("key leaked: %v", err)
	}
}

func TestFetchInvalidJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<html>nope</html>`)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	_, err := c.Fetch(context.Background(), "example.com", "k1")
	if err == nil {
		t.Fatal("expected json error")
	}
}

func TestFetchHTTP204(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewWithOptions(srv.URL, srv.Client())
	_, err := c.Fetch(context.Background(), "example.com", "k1")
	if !IsKeyError(err) {
		t.Fatalf("err=%v", err)
	}
}

func TestMissingAPIKey(t *testing.T) {
	t.Parallel()

	c := New()
	_, err := c.Fetch(context.Background(), "example.com", "  ")
	if !IsKeyError(err) {
		t.Fatalf("err=%v", err)
	}
}
