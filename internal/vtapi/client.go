package vtapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://www.virustotal.com/vtapi/v2/domain/report"
	defaultTimeout = 30 * time.Second
	maxBodyBytes   = 32 * 1024 * 1024
)

type KeyErrorKind int

const (
	KeyRejected KeyErrorKind = iota
	KeyQuota
)

type KeyError struct {
	Reason string
	Kind   KeyErrorKind
}

func (e KeyError) Error() string {
	return e.Reason
}

func IsKeyError(err error) bool {
	var ke KeyError
	return errors.As(err, &ke)
}

func IsQuotaError(err error) bool {
	var ke KeyError
	return errors.As(err, &ke) && ke.Kind == KeyQuota
}

type Client struct {
	http    *http.Client
	baseURL string
}

func New() *Client {
	return NewWithOptions(defaultBaseURL, nil)
}

func NewWithOptions(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		http:    httpClient,
		baseURL: baseURL,
	}
}

func (c *Client) Fetch(ctx context.Context, domain, apiKey string) ([]byte, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, KeyError{Reason: "API key is missing", Kind: KeyRejected}
	}

	reqURL, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VirusTotal endpoint")
	}
	q := reqURL.Query()
	q.Set("apikey", apiKey)
	q.Set("domain", domain)
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vt/1.0 (A-TURBO-99)")

	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, fmt.Errorf("request timed out while querying VirusTotal for %s", domain)
		}
		return nil, fmt.Errorf("network error while querying VirusTotal for %s: %w", domain, sanitize(err))
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read VirusTotal response for %s: %w", domain, err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("VirusTotal response for %s is too large", domain)
	}

	if err := classifyHTTP(resp.StatusCode); err != nil {
		return nil, err
	}

	if err := classifyAPI(body); err != nil {
		return nil, err
	}

	return body, nil
}

func classifyHTTP(status int) error {
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusNoContent:
		return KeyError{Reason: "API rate limit or quota exceeded", Kind: KeyQuota}
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return KeyError{Reason: "API key was rejected", Kind: KeyRejected}
	case status == http.StatusTooManyRequests:
		return KeyError{Reason: "API rate limit or quota exceeded", Kind: KeyQuota}
	case status == http.StatusBadRequest:
		return fmt.Errorf("VirusTotal rejected the request (HTTP %d)", status)
	case status == http.StatusNotFound:
		return fmt.Errorf("VirusTotal returned no data for this domain (HTTP %d)", status)
	case status >= 500:
		return fmt.Errorf("VirusTotal server error (HTTP %d)", status)
	default:
		return fmt.Errorf("unexpected VirusTotal HTTP status %d", status)
	}
}

type apiEnvelope struct {
	ResponseCode json.RawMessage `json:"response_code"`
	VerboseMsg   string          `json:"verbose_msg"`
}

func classifyAPI(body []byte) error {
	if len(body) == 0 {
		return fmt.Errorf("empty response from VirusTotal")
	}

	var env apiEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("invalid JSON response from VirusTotal")
	}

	code, ok := parseResponseCode(env.ResponseCode)
	if !ok {
		return nil
	}

	msg := strings.ToLower(strings.TrimSpace(env.VerboseMsg))
	switch code {
	case 0:
		return nil
	case 1:
		return nil
	case -1:
		if looksLikeKeyIssue(msg) {
			return KeyError{Reason: "API key was rejected", Kind: KeyRejected}
		}
		if looksLikeQuota(msg) {
			return KeyError{Reason: "API rate limit or quota exceeded", Kind: KeyQuota}
		}
		if msg != "" {
			return fmt.Errorf("VirusTotal error: %s", env.VerboseMsg)
		}
		return fmt.Errorf("VirusTotal returned an error")
	case -2:
		if looksLikeQuota(msg) {
			return KeyError{Reason: "API rate limit or quota exceeded", Kind: KeyQuota}
		}
		if looksLikeKeyIssue(msg) {
			return KeyError{Reason: "API key was rejected", Kind: KeyRejected}
		}
		return nil
	default:
		if looksLikeKeyIssue(msg) {
			return KeyError{Reason: "API key was rejected", Kind: KeyRejected}
		}
		if looksLikeQuota(msg) {
			return KeyError{Reason: "API rate limit or quota exceeded", Kind: KeyQuota}
		}
		return nil
	}
}

func parseResponseCode(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		switch s {
		case "0":
			return 0, true
		case "1":
			return 1, true
		case "-1":
			return -1, true
		case "-2":
			return -2, true
		}
	}
	return 0, false
}

func looksLikeKeyIssue(msg string) bool {
	needles := []string{
		"invalid key",
		"apikey",
		"api key",
		"wrong key",
		"missing key",
		"not authenticated",
		"unauthorized",
		"forbidden",
		"authentication",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

func looksLikeQuota(msg string) bool {
	needles := []string{
		"rate limit",
		"quota",
		"exceeded",
		"too many",
		"limit reached",
		"request rate",
		"throttl",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func sanitize(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redactSecrets(err.Error()))
}

func redactSecrets(msg string) string {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "apikey=") {
		return "network error contacting VirusTotal"
	}
	return msg
}
