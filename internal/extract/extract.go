package extract

import (
	"encoding/json"
	"strings"

	"github.com/A-TURBO-99/vt/internal/unique"
)

type Mode int

const (
	ModeNone Mode = iota
	ModeURLs
	ModeSubdomains
	ModeAll
)

type Result struct {
	URLs       []string
	Subdomains []string
}

func ParseMode(urls, subdomains, all bool) (Mode, error) {
	selected := 0
	if urls {
		selected++
	}
	if subdomains {
		selected++
	}
	if all {
		selected++
	}
	if selected == 0 {
		return ModeNone, parseError("extraction mode required: use -u, -s, or -a")
	}
	if selected > 1 {
		return ModeNone, parseError("conflicting extraction modes: use only one of -u, -s, or -a")
	}
	switch {
	case urls:
		return ModeURLs, nil
	case subdomains:
		return ModeSubdomains, nil
	default:
		return ModeAll, nil
	}
}

type reportRaw struct {
	DetectedURLs   json.RawMessage `json:"detected_urls"`
	UndetectedURLs json.RawMessage `json:"undetected_urls"`
	Subdomains     json.RawMessage `json:"subdomains"`
}

type detectedURL struct {
	URL string `json:"url"`
}

// undetectedURL unmarshals VirusTotal's mixed array:
// ["https://example.com/", "hash", 0, 90, "2026-09-22 15:47:55"]
type undetectedURL struct {
	URL string
}

func (u *undetectedURL) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	var url string
	if err := json.Unmarshal(raw[0], &url); err != nil {
		return nil
	}
	u.URL = url
	return nil
}

func FromJSON(body []byte, mode Mode) (Result, error) {
	if len(body) == 0 {
		return Result{}, parseError("empty response from VirusTotal")
	}

	var raw reportRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{}, parseError("invalid JSON response from VirusTotal")
	}

	var out Result
	if mode == ModeURLs || mode == ModeAll {
		out.URLs = extractURLs(raw)
	}
	if mode == ModeSubdomains || mode == ModeAll {
		out.Subdomains = extractSubdomains(raw)
	}
	return out, nil
}

func extractURLs(raw reportRaw) []string {
	set := unique.New()

	var detected []detectedURL
	if len(raw.DetectedURLs) > 0 && string(raw.DetectedURLs) != "null" {
		_ = json.Unmarshal(raw.DetectedURLs, &detected)
	}
	for _, item := range detected {
		set.Add(strings.TrimSpace(item.URL))
	}

	var undetected []undetectedURL
	if len(raw.UndetectedURLs) > 0 && string(raw.UndetectedURLs) != "null" {
		_ = json.Unmarshal(raw.UndetectedURLs, &undetected)
	}
	for _, item := range undetected {
		set.Add(strings.TrimSpace(item.URL))
	}

	return set.Values()
}

func extractSubdomains(raw reportRaw) []string {
	set := unique.New()
	var subs []string
	if len(raw.Subdomains) > 0 && string(raw.Subdomains) != "null" {
		_ = json.Unmarshal(raw.Subdomains, &subs)
	}
	for _, item := range subs {
		set.Add(strings.TrimSpace(item))
	}
	return set.Values()
}

type parseError string

func (e parseError) Error() string { return string(e) }
