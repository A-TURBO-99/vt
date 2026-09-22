package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	APIKey1 string `json:"api_key_1"`
	APIKey2 string `json:"api_key_2"`
}

func (c Config) Primary() string {
	return normalizeKey(c.APIKey1)
}

func (c Config) Fallback() string {
	return normalizeKey(c.APIKey2)
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

	if cfg.Primary() == "" {
		return Config{}, "", fmt.Errorf("missing primary API key in %s (set api_key_1)", path)
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
