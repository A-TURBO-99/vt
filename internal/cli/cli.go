package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/A-TURBO-99/vt/internal/banner"
	"github.com/A-TURBO-99/vt/internal/config"
	"github.com/A-TURBO-99/vt/internal/extract"
	"github.com/A-TURBO-99/vt/internal/input"
	"github.com/A-TURBO-99/vt/internal/output"
	"github.com/A-TURBO-99/vt/internal/unique"
	"github.com/A-TURBO-99/vt/internal/vtapi"
)

const (
	defaultThreads    = 1
	defaultRequestGap = time.Second
	usageText         = `vt — VirusTotal domain reconnaissance

Usage:
  vt -d <domain>  -u|-s|-a  [-o file] [-t n] [-dl seconds]
  vt -l <file>    -u|-s|-a  [-o file] [-t n] [-dl seconds]

Flags:
  -d     Single domain or subdomain
  -l     File with one domain per line
  -u     Extract URLs
  -s     Extract subdomains
  -a     Extract URLs and subdomains
  -o     Save results to a file
  -t     Number of threads (default 1)
  -dl    Delay in seconds between requests (default 1, 0 disables)
  -c     Path to config.json (optional)
  -h     Show help

Examples:
  vt -d example.com -u
  vt -d example.com -s
  vt -d example.com -a
  vt -l domains.txt -u
  vt -l domains.txt -u -t 5
  vt -l domains.txt -u -t 5 -dl 0.5
  vt -d example.com -u -o urls.txt
  vt -d example.com -u | sort -u
`
)

type Options struct {
	Domain   string
	ListFile string
	URLs     bool
	Subs     bool
	All      bool
	Output   string
	Config   string
	Threads  int
	Delay    float64
	DelaySet bool
	Help     bool
}

func Parse(args []string) (Options, error) {
	fs := flag.NewFlagSet("vt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var opt Options
	fs.StringVar(&opt.Domain, "d", "", "single domain")
	fs.StringVar(&opt.ListFile, "l", "", "input file")
	fs.BoolVar(&opt.URLs, "u", false, "extract URLs")
	fs.BoolVar(&opt.Subs, "s", false, "extract subdomains")
	fs.BoolVar(&opt.All, "a", false, "extract URLs and subdomains")
	fs.StringVar(&opt.Output, "o", "", "output file")
	fs.StringVar(&opt.Config, "c", "", "config file path")
	fs.IntVar(&opt.Threads, "t", defaultThreads, "threads")
	fs.Float64Var(&opt.Delay, "dl", 1, "delay in seconds between requests")
	fs.BoolVar(&opt.Help, "h", false, "help")
	fs.BoolVar(&opt.Help, "help", false, "help")

	if err := fs.Parse(args); err != nil {
		return Options{}, fmt.Errorf("%v\n\n%s", err, usageText)
	}
	if fs.NArg() > 0 {
		return Options{}, fmt.Errorf("unexpected argument: %s\n\n%s", fs.Arg(0), usageText)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "dl" {
			opt.DelaySet = true
		}
	})
	return opt, nil
}

func Usage() string { return usageText }

type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Client *vtapi.Client
	// DefaultDelay is used when -dl is not supplied on the command line.
	DefaultDelay time.Duration
}

func NewApp() *App {
	return &App{
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
		Client:       vtapi.New(),
		DefaultDelay: defaultRequestGap,
	}
}

func (a *App) Run(ctx context.Context, args []string) int {
	opt, err := Parse(args)
	if err != nil {
		fmt.Fprintln(a.Stderr, err.Error())
		return 2
	}
	if opt.Help {
		banner.Print(a.Stderr)
		fmt.Fprintln(a.Stderr)
		fmt.Fprint(a.Stderr, usageText)
		return 0
	}

	if opt.Threads < 1 {
		fmt.Fprintf(a.Stderr, "[-] -t must be at least 1\n\n%s", usageText)
		return 2
	}

	if opt.DelaySet && opt.Delay < 0 {
		fmt.Fprintf(a.Stderr, "[-] -dl cannot be negative\n\n%s", usageText)
		return 2
	}

	mode, err := extract.ParseMode(opt.URLs, opt.Subs, opt.All)
	if err != nil {
		fmt.Fprintf(a.Stderr, "[-] %s\n\n%s", err.Error(), usageText)
		return 2
	}

	targets, err := input.LoadTargets(opt.Domain, opt.ListFile)
	if err != nil {
		fmt.Fprintf(a.Stderr, "[-] %s\n", err.Error())
		return 2
	}

	cfg, _, err := config.Load(opt.Config)
	if err != nil {
		fmt.Fprintf(a.Stderr, "[-] %s\n", err.Error())
		return 2
	}

	out, err := output.New(a.Stdout, a.Stderr, opt.Output)
	if err != nil {
		fmt.Fprintf(a.Stderr, "[-] %s\n", err.Error())
		return 1
	}
	defer func() {
		if cerr := out.Close(); cerr != nil {
			fmt.Fprintf(a.Stderr, "[-] %s\n", cerr.Error())
		}
	}()

	banner.Print(a.Stderr)
	fmt.Fprintln(a.Stderr)

	client := a.Client
	if client == nil {
		client = vtapi.New()
	}

	gap := a.DefaultDelay
	if opt.DelaySet {
		gap = time.Duration(opt.Delay * float64(time.Second))
	}
	if gap < 0 {
		gap = 0
	}
	rotator := newKeyRotator(cfg.Keys(), client, out)
	slots := startWorkers(ctx, rotator, targets, mode, opt.Threads, newRateLimiter(gap))

	globalURLs := unique.New()
	globalSubs := unique.New()
	failures := 0

	for i, domain := range targets {
		out.Statusf("[+] Processing: %s", domain)

		var outcome domainOutcome
		select {
		case <-ctx.Done():
			out.Errorf("interrupted")
			return 1
		case outcome = <-slots[i]:
		}

		if outcome.err != nil {
			if errors.Is(outcome.err, context.Canceled) || errors.Is(outcome.err, context.DeadlineExceeded) {
				out.Errorf("interrupted")
				return 1
			}
			out.Errorf("%s: %s", domain, sanitizeUserError(outcome.err))
			failures++
			continue
		}

		res := outcome.res
		if mode == extract.ModeURLs || mode == extract.ModeAll {
			out.Statusf("[+] Found %d URLs", len(res.URLs))
		}
		if mode == extract.ModeSubdomains || mode == extract.ModeAll {
			out.Statusf("[+] Found %d Subdomains", len(res.Subdomains))
		}

		newURLs := takeNew(globalURLs, res.URLs)
		newSubs := takeNew(globalSubs, res.Subdomains)

		fmt.Fprintln(a.Stderr)

		if err := out.WriteResults(newURLs); err != nil {
			out.Errorf("%s", err.Error())
			return 1
		}
		if mode == extract.ModeAll && len(newURLs) > 0 && len(newSubs) > 0 {
			if err := out.BlankLine(); err != nil {
				out.Errorf("%s", err.Error())
				return 1
			}
		}
		if err := out.WriteResults(newSubs); err != nil {
			out.Errorf("%s", err.Error())
			return 1
		}
		if len(newURLs) > 0 || len(newSubs) > 0 {
			fmt.Fprintln(a.Stderr)
		}
	}

	if opt.Output != "" {
		out.Statusf("[+] Saved results to %s", opt.Output)
	}

	if failures > 0 && failures == len(targets) {
		return 1
	}
	return 0
}

func takeNew(set *unique.Set, values []string) []string {
	var out []string
	for _, v := range values {
		if set.Add(v) {
			out = append(out, v)
		}
	}
	return out
}

func sanitizeUserError(err error) string {
	if err == nil {
		return "unknown error"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "apikey=") || strings.Contains(lower, "api_key") {
		return "VirusTotal request failed"
	}
	return msg
}
