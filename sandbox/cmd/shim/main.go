package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tinfoil/internal/bootstate"
	"tinfoil/shim"
)

func main() {
	log.SetFlags(0)
	var options shim.Options
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&options.ConfigFile, "c", bootstate.ShimConfigPath, "Path to config file")
	flags.StringVar(&options.ExternalConfigFile, "e", bootstate.ExternalConfigPath, "Path to external config file")
	flags.Parse(os.Args[1:])
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := shim.Run(ctx, options, shimSpec()); err != nil {
		log.Fatal(err)
	}
}
