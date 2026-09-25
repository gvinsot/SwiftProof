package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/gvinsot/SwiftProof/app/internal/cli"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, version)
	stop()
	os.Exit(code)
}
