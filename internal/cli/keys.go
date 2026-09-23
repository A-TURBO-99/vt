package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/A-TURBO-99/vt/internal/output"
	"github.com/A-TURBO-99/vt/internal/vtapi"
)

type keyRotator struct {
	mu      sync.Mutex
	keys    []string
	current int
	client  *vtapi.Client
	out     *output.Writer
}

func newKeyRotator(keys []string, client *vtapi.Client, out *output.Writer) *keyRotator {
	return &keyRotator{
		keys:   keys,
		client: client,
		out:    out,
	}
}

func (r *keyRotator) Fetch(ctx context.Context, domain string) ([]byte, error) {
	for {
		key, idx, ok := r.currentKey()
		if !ok {
			return nil, fmt.Errorf("all API keys are exhausted")
		}

		body, err := r.client.Fetch(ctx, domain, key)
		if err == nil {
			return body, nil
		}
		if !vtapi.IsKeyError(err) {
			return nil, err
		}

		if vtapi.IsQuotaError(err) {
			r.report("API rate limit or quota exceeded")
			if !r.advance(idx) {
				return nil, fmt.Errorf("all API keys are exhausted")
			}
			r.reportSwitch()
			continue
		}

		r.report("API key was rejected")
		if !r.advance(idx) {
			return nil, fmt.Errorf("all API keys are exhausted")
		}
		r.reportSwitch()
	}
}

func (r *keyRotator) currentKey() (string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current < 0 || r.current >= len(r.keys) {
		return "", r.current, false
	}
	return r.keys[r.current], r.current, true
}

func (r *keyRotator) advance(from int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == from {
		r.current++
	}
	return r.current < len(r.keys)
}

func (r *keyRotator) report(msg string) {
	if r.out != nil {
		r.out.Errorf("%s", msg)
	}
}

func (r *keyRotator) reportSwitch() {
	if r.out != nil {
		r.out.Statusf("[+] Switching to the next API key")
	}
}
