package cli

import (
	"context"
	"sync"

	"github.com/A-TURBO-99/vt/internal/config"
	"github.com/A-TURBO-99/vt/internal/extract"
	"github.com/A-TURBO-99/vt/internal/vtapi"
)

type domainOutcome struct {
	domain string
	res    extract.Result
	err    error
}

func startWorkers(ctx context.Context, client *vtapi.Client, cfg config.Config, targets []string, mode extract.Mode, threads int, limiter *rateLimiter) []<-chan domainOutcome {
	n := len(targets)
	slots := make([]chan domainOutcome, n)
	out := make([]<-chan domainOutcome, n)
	for i := range slots {
		ch := make(chan domainOutcome, 1)
		slots[i] = ch
		out[i] = ch
	}
	if n == 0 {
		return out
	}

	if threads < 1 {
		threads = 1
	}
	if threads > n {
		threads = n
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				domain := targets[idx]
				if err := ctx.Err(); err != nil {
					slots[idx] <- domainOutcome{domain: domain, err: err}
					continue
				}
				if err := limiter.Wait(ctx); err != nil {
					slots[idx] <- domainOutcome{domain: domain, err: err}
					continue
				}

				body, err := fetchWithFallback(ctx, client, domain, cfg)
				if err != nil {
					slots[idx] <- domainOutcome{domain: domain, err: err}
					continue
				}

				res, err := extract.FromJSON(body, mode)
				slots[idx] <- domainOutcome{domain: domain, res: res, err: err}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for i := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- i:
			}
		}
	}()

	go func() {
		wg.Wait()
		for i := range slots {
			select {
			case slots[i] <- domainOutcome{domain: targets[i], err: ctx.Err()}:
			default:
			}
		}
	}()

	return out
}
