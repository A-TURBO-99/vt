package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config supports an unlimited api_keys array and the legacy api_key_1 through
// api_key_10 fields for backward compatibility.
type Config struct {
	APIKeys []string `json:"api_keys"`

	APIKey1  string `json:"api_key_1"`
	APIKey2  string `json:"api_key_2"`
	APIKey3  string `json:"api_key_3"`
	APIKey4  string `json:"api_key_4"`
	APIKey5  string `json:"api_key_5"`
	APIKey6  string `json:"api_key_6"`
	APIKey7  string `json:"api_key_7"`
	APIKey8  string `json:"api_key_8"`
	APIKey9  string `json:"api_key_9"`
	APIKey10 string `json:"api_key_10"`
}

// Keys returns configured API keys in order, trimming whitespace and
// discarding empty values, placeholders, and duplicates. The dynamic array
// comes first; legacy fields are appended so old config files keep working.
func (c Config) Keys() []string {
	raw := make([]string, 0, len(c.APIKeys)+10)
	raw = append(raw, c.APIKeys...)
	raw = append(raw,
		c.APIKey1, c.APIKey2, c.APIKey3, c.APIKey4, c.APIKey5,
		c.APIKey6, c.APIKey7, c.APIKey8, c.APIKey9, c.APIKey10,
	)

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, key := range raw {
		key = normalizeKey(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func Load(explicitPath string) (Config, string, error) {
	path, err := resolvePath(explicitPath)
	if err != nil {
		return Config{}, "", err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, "", fmt.Errorf("unable to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, "", fmt.Errorf("invalid configuration file %s: %w", path, err)
	}

	if len(cfg.Keys()) == 0 {
		return Config{}, "", fmt.Errorf("missing API key in %s (set api_keys or api_key_1)", path)
	}

	return cfg, path, nil
}

func resolvePath(explicitPath string) (string, error) {
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("config file not found: %s", explicitPath)
		}
		return explicitPath, nil
	}

	for _, candidate := range candidates() {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("config file not found; copy config/config.json.example to config/config.json and add your API keys")
}

func candidates() []string {
	out := []string{
		filepath.Join("config", "config.json"),
		"config.json",
	}

	if cwd, err := os.Getwd(); err == nil {
		out = append(out,
			filepath.Join(cwd, "config", "config.json"),
			filepath.Join(cwd, "config.json"),
		)
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, "config", "config.json"),
			filepath.Join(dir, "config.json"),
		)
	}

	seen := make(map[string]struct{})
	uniq := make([]string, 0, len(out))
	for _, p := range out {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		uniq = append(uniq, abs)
	}
	return uniq
}

func normalizeKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	upper := strings.ToUpper(value)
	switch upper {
	case "YOUR_PRIMARY_API_KEY", "YOUR_FALLBACK_API_KEY", "YOUR_API_KEY":
		return ""
	}
	if strings.HasPrefix(upper, "YOUR_") {
		return ""
	}
	return value
}
