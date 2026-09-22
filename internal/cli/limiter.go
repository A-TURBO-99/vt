package cli

import (
	"context"
	"sync"
	"time"
)

type rateLimiter struct {
	mu     sync.Mutex
	minGap time.Duration
	next   time.Time
}

func newRateLimiter(minGap time.Duration) *rateLimiter {
	if minGap <= 0 {
		return nil
	}
	return &rateLimiter{minGap: minGap}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return ctx.Err()
	}

	r.mu.Lock()
	now := time.Now()
	waitUntil := r.next
	if waitUntil.IsZero() || !now.Before(waitUntil) {
		r.next = now.Add(r.minGap)
		r.mu.Unlock()
		return ctx.Err()
	}
	r.next = waitUntil.Add(r.minGap)
	r.mu.Unlock()

	timer := time.NewTimer(time.Until(waitUntil))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
