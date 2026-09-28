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
	if err != nil || mode != ModeIPs {
		t.Fatalf("ips mode: mode=%v err=%v", mode, err)
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

	res, err := FromJSON(body, ModeURLs)
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

	subs, err := FromJSON(body, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	wantSubs := []string{"blog.example.com", "api.example.com"}
	if len(subs.Subdomains) != len(wantSubs) {
		t.Fatalf("subs=%v", subs.Subdomains)
	}
	for i, s := range wantSubs {
		if subs.Subdomains[i] != s {
			t.Fatalf("sub[%d]=%q want %q", i, subs.Subdomains[i], s)
		}
	}
}

func TestFromJSONMissingFields(t *testing.T) {
	t.Parallel()

	res, err := FromJSON([]byte(`{"response_code": 1}`), ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.URLs) != 0 || len(res.Subdomains) != 0 || len(res.IPs) != 0 {
		t.Fatalf("expected empty results, got %+v", res)
	}
	ips, err := FromJSON([]byte(`{"response_code": 1}`), ModeIPs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips.IPs) != 0 {
		t.Fatalf("expected empty IPs, got %+v", ips)
	}
}

func TestFromJSONUnexpectedStructures(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"detected_urls": {"not": "an array"},
		"undetected_urls": "oops",
		"subdomains": 12
	}`)
	res, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.URLs) != 0 || len(res.Subdomains) != 0 {
		t.Fatalf("expected empty results for unexpected structures, got %+v", res)
	}
	ips, err := FromJSON(body, ModeIPs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips.IPs) != 0 {
		t.Fatalf("expected empty IPs for unexpected structures, got %+v", ips)
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

func TestFromJSONIPResolutions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"as_owner": "Google LLC",
		"asn": 15169,
		"country": "BE",
		"detected_urls": [
			{"positives": 1, "scan_date": "2021-11-25 07:59:25", "total": 93, "url": "http://forms.kycaid.com/"}
		],
		"resolutions": [
			{"hostname": "admin.kycaid.com", "last_resolved": "2019-09-21 04:56:13"},
			{"hostname": "api.kycaid.com", "last_resolved": "2019-09-21 04:56:13"},
			{"hostname": "admin.kycaid.com", "last_resolved": "2018-01-01 00:00:00"}
		],
		"undetected_urls": [
			["http://kycaid.com/", "hash", 0, 90, "2023-08-13 00:34:26"]
		]
	}`)

	res, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	wantURLs := []string{"http://forms.kycaid.com/", "http://kycaid.com/"}
	if len(res.URLs) != len(wantURLs) {
		t.Fatalf("urls=%v", res.URLs)
	}
	for i, u := range wantURLs {
		if res.URLs[i] != u {
			t.Fatalf("url[%d]=%q want %q", i, res.URLs[i], u)
		}
	}
	hosts, err := FromJSON(body, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	wantHosts := []string{"admin.kycaid.com", "api.kycaid.com"}
	if len(hosts.Subdomains) != len(wantHosts) {
		t.Fatalf("subs=%v", hosts.Subdomains)
	}
	for i, s := range wantHosts {
		if hosts.Subdomains[i] != s {
			t.Fatalf("sub[%d]=%q want %q", i, hosts.Subdomains[i], s)
		}
	}

	urlsOnly, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(urlsOnly.URLs) != 2 || len(urlsOnly.Subdomains) != 0 {
		t.Fatalf("urls mode: %+v", urlsOnly)
	}

	subsOnly, err := FromJSON(body, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	if len(subsOnly.URLs) != 0 || len(subsOnly.Subdomains) != 2 {
		t.Fatalf("subs mode: %+v", subsOnly)
	}
}

func TestFromJSONExtractsIPs(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"response_code": 1,
		"resolutions": [
			{"hostname": "api.example.com", "ip_address": "1.2.3.4", "last_resolved": "2024-01-01 00:00:00"},
			{"hostname": "www.example.com", "ip_address": "1.2.3.4", "last_resolved": "2024-01-02 00:00:00"},
			{"hostname": "mail.example.com", "ip_address": "5.6.7.8", "last_resolved": "2024-01-03 00:00:00"},
			{"hostname": "empty.example.com", "ip_address": "", "last_resolved": "2024-01-04 00:00:00"},
			{"hostname": "bad.example.com", "ip_address": "not-an-ip", "last_resolved": "2024-01-05 00:00:00"},
			{"hostname": "noip.example.com", "last_resolved": "2024-01-06 00:00:00"}
		],
		"detected_urls": [{"url": "https://example.com/"}],
		"subdomains": ["api.example.com"]
	}`)

	res, err := FromJSON(body, ModeIPs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4", "5.6.7.8"}
	if len(res.IPs) != len(want) {
		t.Fatalf("ips=%v", res.IPs)
	}
	for i, ip := range want {
		if res.IPs[i] != ip {
			t.Fatalf("ip[%d]=%q want %q", i, res.IPs[i], ip)
		}
	}
	if len(res.URLs) != 0 || len(res.Subdomains) != 0 {
		t.Fatalf("ips mode should not extract urls/subs: %+v", res)
	}
}

func TestModeFilters(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"detected_urls": [{"url": "https://example.com/"}],
		"subdomains": ["api.example.com"],
		"resolutions": [{"hostname": "api.example.com", "ip_address": "1.2.3.4"}]
	}`)

	urls, err := FromJSON(body, ModeURLs)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls.URLs) != 1 || len(urls.Subdomains) != 0 || len(urls.IPs) != 0 {
		t.Fatalf("urls mode: %+v", urls)
	}

	subs, err := FromJSON(body, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs.URLs) != 0 || len(subs.Subdomains) != 1 || len(subs.IPs) != 0 {
		t.Fatalf("subs mode: %+v", subs)
	}

	ips, err := FromJSON(body, ModeIPs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips.URLs) != 0 || len(ips.Subdomains) != 0 || len(ips.IPs) != 1 {
		t.Fatalf("ips mode: %+v", ips)
	}
}
