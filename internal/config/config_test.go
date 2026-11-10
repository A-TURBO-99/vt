package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDynamicKeysBeyondTen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	keys := make([]string, 25)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i+1)
	}
	// Build JSON as an array.
	jsonKeys := "["
	for i, key := range keys {
		if i > 0 {
			jsonKeys += ","
		}
		jsonKeys += fmt.Sprintf(`%q`, key)
	}
	jsonKeys += "]"
	data := `{"api_keys":` + jsonKeys + `}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != path {
		t.Fatalf("loaded=%s", loaded)
	}
	got := cfg.Keys()
	if len(got) != 25 {
		t.Fatalf("expected 25 keys, got %d: %v", len(got), got)
	}
	for i, key := range keys {
		if got[i] != key {
			t.Fatalf("key[%d]=%q want %q", i, got[i], key)
		}
	}
}

func TestLoadLegacyTenKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
		"api_key_1":" k1 ",
		"api_key_2":"k2",
		"api_key_3":"k3",
		"api_key_4":"k4",
		"api_key_5":"k5",
		"api_key_6":"k6",
		"api_key_7":"k7",
		"api_key_8":"k8",
		"api_key_9":"k9",
		"api_key_10":"k10"
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Keys()
	if len(got) != 10 {
		t.Fatalf("keys=%v", got)
	}
	for i := range got {
		if got[i] != fmt.Sprintf("k%d", i+1) {
			t.Fatalf("keys=%v", got)
		}
	}
}

func TestKeysCombinesDynamicAndLegacyWithoutDuplicates(t *testing.T) {
	cfg := Config{
		APIKeys:  []string{" k1 ", "", "YOUR_API_KEY_3", "k2", "k1"},
		APIKey1:  "k2",
		APIKey2:  "k3",
		APIKey10: "k3",
	}
	got := cfg.Keys()
	want := []string{"k1", "k2", "k3"}
	if len(got) != len(want) {
		t.Fatalf("keys=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys=%v", got)
		}
	}
}

func TestLoadRejectsPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{"api_keys":["YOUR_PRIMARY_API_KEY", ""]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected missing API key error")
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
