package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"tinfoil/boot"
)

func main() {
	log.SetFlags(0)
	options, err := parseInvocation(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Println("Tinfoil boot starting")
	if err := boot.Run(ctx, options, bootSpec()); err != nil {
		log.Fatalf("Boot failed: %v", err)
	}
	log.Println("Tinfoil boot complete")
}

func parseInvocation(args []string) (boot.Options, error) {
	if len(args) == 0 {
		return boot.Options{}, fmt.Errorf("missing argv[0]")
	}
	var options boot.Options
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.ConfigHash, "config-hash", "", "verified config hash from the kernel command line")
	flags.BoolVar(&options.Debug, "debug", false, "enable the measured debug policy")
	flags.IntVar(&options.SecretsFD, "secrets-fd", -1, "sealed workload-secret handoff descriptor")
	if err := flags.Parse(args[1:]); err != nil {
		return boot.Options{}, err
	}
	if flags.NArg() != 0 {
		return boot.Options{}, fmt.Errorf("tinfoil-boot does not accept maintenance commands")
	}
	return options, nil
}
