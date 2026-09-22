package extract

import (
	"testing"
)

func TestParseMode(t *testing.T) {
	t.Parallel()

	mode, err := ParseMode(true, false, false)
	if err != nil || mode != ModeURLs {
		t.Fatalf("urls mode: mode=%v err=%v", mode, err)
	}

	mode, err = ParseMode(false, true, false)
	if err != nil || mode != ModeSubdomains {
		t.Fatalf("subdomains mode: mode=%v err=%v", mode, err)
	}

	mode, err = ParseMode(false, false, true)
	if err != nil || mode != ModeAll {
		t.Fatalf("all mode: mode=%v err=%v", mode, err)
	}

	if _, err := ParseMode(false, false, false); err == nil {
		t.Fatal("expected error when no mode is selected")
	}
	if _, err := ParseMode(true, true, false); err == nil {
		t.Fatal("expected error for conflicting modes")
	}
	if _, err := ParseMode(true, false, true); err == nil {
		t.Fatal("expected error for conflicting modes")
	}
}

func TestFromJSONExtractsBothURLShapes(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"response_code": 1,
		"detected_urls": [
			{"positives": 1, "scan_date": "2024-11-12 11:23:09", "total": 96, "url": "https://example.com/page"},
			{"url": "https://example.com/"},
			{"url": "https://example.com/page"}
		],
		"undetected_urls": [
			["https://example.com/", "hash", 0, 90, "2026-09-22 15:47:55"],
			["https://example.com/blog/", "abc", 0, 90, "2026-09-22 15:47:55"]
		],
		"subdomains": ["blog.example.com", "api.example.com", "blog.example.com"]
	}`)

	res, err := FromJSON(body, ModeAll)
	if err != nil {
		t.Fatal(err)
	}

	wantURLs := []string{
		"https://example.com/page",
		"https://example.com/",
		"https://example.com/blog/",
	}
	if len(res.URLs) != len(wantURLs) {
		t.Fatalf("urls=%v", res.URLs)
	}
	for i, u := range wantURLs {
		if res.URLs[i] != u {
			t.Fatalf("url[%d]=%q want %q", i, res.URLs[i], u)
		}
	}

	wantSubs := []string{"blog.example.com", "api.example.com"}
	if len(res.Subdomains) != len(wantSubs) {
		t.Fatalf("subs=%v", res.Subdomains)
	}
	for i, s := range wantSubs {
		if res.Subdomains[i] != s {
			t.Fatalf("sub[%d]=%q want %q", i, res.Subdomains[i], s)
		}
	}
}

func TestFromJSONMissingFields(t *testing.T) {
	t.Parallel()

	res, err := FromJSON([]byte(`{"response_code": 1}`), ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.URLs) != 0 || len(res.Subdomains) != 0 {
		t.Fatalf("expected empty results, got %+v", res)
	}
}

func TestFromJSONUnexpectedStructures(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"detected_urls": {"not": "an array"},
		"undetected_urls": "oops",
		"subdomains": 12
	}`)
	res, err := FromJSON(body, ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.URLs) != 0 || len(res.Subdomains) != 0 {
		t.Fatalf("expected empty results for unexpected structures, got %+v", res)
	}
}

func TestFromJSONInvalid(t *testing.T) {
	t.Parallel()

	if _, err := FromJSON([]byte(`not-json`), ModeURLs); err == nil {
		t.Fatal("expected invalid JSON error")
	}
	if _, err := FromJSON(nil, ModeURLs); err == nil {
		t.Fatal("expected empty body error")
	}
}

func TestFromJSONUndetectedMalformedRows(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"undetected_urls": [
			[],
			[123, "hash"],
			["https://ok.example/"]
		]
	}`)
	res, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.URLs) != 1 || res.URLs[0] != "https://ok.example/" {
		t.Fatalf("urls=%v", res.URLs)
	}
}

func TestModeFilters(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"detected_urls": [{"url": "https://example.com/"}],
		"subdomains": ["api.example.com"]
	}`)

	urls, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls.URLs) != 1 || len(urls.Subdomains) != 0 {
		t.Fatalf("urls mode: %+v", urls)
	}

	subs, err := FromJSON(body, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs.URLs) != 0 || len(subs.Subdomains) != 1 {
		t.Fatalf("subs mode: %+v", subs)
	}
}
