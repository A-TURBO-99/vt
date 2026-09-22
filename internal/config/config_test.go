package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrimaryAndFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{"api_key_1":" primary-key ","api_key_2":"fallback-key"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != path {
		t.Fatalf("loaded=%s", loaded)
	}
	if cfg.Primary() != "primary-key" {
		t.Fatalf("primary=%q", cfg.Primary())
	}
	if cfg.Fallback() != "fallback-key" {
		t.Fatalf("fallback=%q", cfg.Fallback())
	}
}

func TestLoadRejectsPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{"api_key_1":"YOUR_PRIMARY_API_KEY","api_key_2":""}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected missing primary key error")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected missing file error")
	}
}

func TestEmptyFallback(t *testing.T) {
	cfg := Config{APIKey1: "abc", APIKey2: "   "}
	if cfg.Fallback() != "" {
		t.Fatalf("fallback=%q", cfg.Fallback())
	}
}
