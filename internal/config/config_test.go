package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTenKeys(t *testing.T) {
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

	cfg, loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != path {
		t.Fatalf("loaded=%s", loaded)
	}
	got := cfg.Keys()
	want := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10"}
	if len(got) != len(want) {
		t.Fatalf("keys=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys=%v", got)
		}
	}
}

func TestLoadSkipsEmptyAndPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := []byte(`{
		"api_key_1":"k1",
		"api_key_2":"",
		"api_key_3":"YOUR_API_KEY_3",
		"api_key_4":"k4",
		"api_key_5":"k1",
		"api_key_6":"",
		"api_key_7":"YOUR_API_KEY_7",
		"api_key_8":"k8",
		"api_key_9":"k8",
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
	want := []string{"k1", "k4", "k8", "k10"}
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
