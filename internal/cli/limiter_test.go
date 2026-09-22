package cli

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterSpacing(t *testing.T) {
	t.Parallel()

	lim := newRateLimiter(40 * time.Millisecond)
	start := time.Now()
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 80*time.Millisecond {
		t.Fatalf("elapsed=%s, expected at least 80ms between 3 requests", elapsed)
	}
}

func TestRateLimiterNil(t *testing.T) {
	t.Parallel()

	var lim *rateLimiter
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimiterCancel(t *testing.T) {
	t.Parallel()

	lim := newRateLimiter(time.Second)
	if err := lim.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lim.Wait(ctx); err == nil {
		t.Fatal("expected cancel")
	}
}
