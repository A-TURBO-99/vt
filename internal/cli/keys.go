package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/A-TURBO-99/vt/internal/output"
	"github.com/A-TURBO-99/vt/internal/vtapi"
)

type keyRotator struct {
	mu       sync.Mutex
	keys     []string
	current  int
	rejected map[int]struct{}
	client   *vtapi.Client
	out      *output.Writer
	limiter  *rateLimiter
}

func newKeyRotator(keys []string, client *vtapi.Client, out *output.Writer, limiter *rateLimiter) *keyRotator {
	return &keyRotator{
		keys:     keys,
		rejected: make(map[int]struct{}),
		client:   client,
		out:      out,
		limiter:  limiter,
	}
}

func (r *keyRotator) Fetch(ctx context.Context, domain string) ([]byte, error) {
	return r.fetch(ctx, domain, false)
}

func (r *keyRotator) FetchIP(ctx context.Context, ip string) ([]byte, error) {
	return r.fetch(ctx, ip, true)
}

func (r *keyRotator) fetch(ctx context.Context, target string, isIP bool) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		key, idx, ok := r.currentKey()
		if !ok {
			return nil, fmt.Errorf("all API keys are exhausted or rejected")
		}

		var (
			body []byte
			err  error
		)
		if isIP {
			body, err = r.client.FetchIP(ctx, target, key)
		} else {
			body, err = r.client.Fetch(ctx, target, key)
		}
		if err == nil {
			return body, nil
		}
		if !vtapi.IsKeyError(err) {
			return nil, err
		}

		if vtapi.IsQuotaError(err) {
			r.report("API rate limit or quota exceeded")
			wrapped, available := r.advance(idx)
			if !available {
				return nil, fmt.Errorf("all API keys are rejected")
			}
			if wrapped {
				r.reportRestart()
			} else {
				r.reportSwitch()
			}
		} else {
			r.report("API key was rejected")
			if !r.reject(idx) {
				return nil, fmt.Errorf("all API keys are rejected")
			}
			r.reportSwitch()
		}

		// Apply -dl to retries too. This prevents key rotation from bypassing
		// the configured request pacing when every key is rate-limited.
		if err := r.limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
}

func (r *keyRotator) currentKey() (string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx, ok := r.nextAvailableLocked(r.current)
	if !ok {
		return "", r.current, false
	}
	r.current = idx
	return r.keys[idx], idx, true
}

// advance moves to the next usable key. Quota-limited keys remain in the
// rotation and are retried after the final usable key, making the sequence
// cyclic. The bool result reports whether the rotation wrapped to the start.
func (r *keyRotator) advance(from int) (wrapped bool, available bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.keys) == 0 {
		return false, false
	}

	start := r.current
	if r.current == from {
		start = (from + 1) % len(r.keys)
	}
	next, ok := r.nextAvailableLocked(start)
	if !ok {
		return false, false
	}

	if r.current == from {
		r.current = next
		return next <= from, true
	}

	// Another worker already advanced the shared index. Do not move it
	// backwards based on a delayed response from an older request.
	r.current = next
	return false, true
}

// reject permanently removes an invalid/rejected key from future rotations.
func (r *keyRotator) reject(index int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if index >= 0 && index < len(r.keys) {
		r.rejected[index] = struct{}{}
	}

	start := r.current
	if r.current == index && len(r.keys) > 0 {
		start = (index + 1) % len(r.keys)
	}
	next, ok := r.nextAvailableLocked(start)
	if !ok {
		return false
	}
	r.current = next
	return true
}

func (r *keyRotator) nextAvailableLocked(start int) (int, bool) {
	if len(r.keys) == 0 {
		return 0, false
	}
	if start < 0 || start >= len(r.keys) {
		start = 0
	}
	for offset := 0; offset < len(r.keys); offset++ {
		idx := (start + offset) % len(r.keys)
		if _, rejected := r.rejected[idx]; !rejected {
			return idx, true
		}
	}
	return 0, false
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

func (r *keyRotator) reportRestart() {
	if r.out != nil {
		r.out.Statusf("[+] Reached the last API key; restarting rotation from the first available API key")
	}
}
