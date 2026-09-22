package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/A-TURBO-99/vt/internal/unique"
)

func LoadTargets(domain, listFile string) ([]string, error) {
	if domain != "" && listFile != "" {
		return nil, fmt.Errorf("use either -d or -l, not both")
	}
	if domain == "" && listFile == "" {
		return nil, fmt.Errorf("a target is required: use -d <domain> or -l <file>")
	}
	if domain != "" {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return nil, fmt.Errorf("domain cannot be empty")
		}
		return []string{domain}, nil
	}
	return loadFile(listFile)
}

func loadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("input file not found: %s", path)
		}
		return nil, fmt.Errorf("unable to open input file %s: %w", path, err)
	}
	defer f.Close()

	set := unique.New()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set.Add(line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input file %s: %w", path, err)
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("input file is empty: %s", path)
	}
	return set.Values(), nil
}
