package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/A-TURBO-99/vt/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cli.NewApp()
	os.Exit(app.Run(ctx, os.Args[1:]))
}
