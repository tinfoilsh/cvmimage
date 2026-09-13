package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tinfoil/internal/runtimeconfig"
	"tinfoil/internal/volume"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == volume.FormatMode {
		if err := volume.RunFormatter(os.Args); err != nil {
			log.Fatalf("tinfoil-volume-worker: %v", err)
		}
		return
	}
	parsed, err := parseInvocation(os.Args)
	if err != nil {
		log.Fatalf("tinfoil-volume-worker: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := volume.Serve(ctx, parsed); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("tinfoil-volume-worker: %v", err)
	}
}

func parseInvocation(args []string) (volume.Spec, error) {
	if len(args) == 0 {
		return volume.Spec{}, errors.New("missing argv[0]")
	}
	var parsed volume.Spec
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.IntVar(&parsed.Models, "models", 0, "")
	flags.IntVar(&parsed.Index, "index", 0, "")
	flags.StringVar(&parsed.Name, "name", "", "")
	flags.BoolVar(&parsed.Exec, "exec", false, "")
	flags.IntVar(&parsed.Owner, "owner", 0, "")
	flags.Func("overlay", "", func(value string) error {
		parts := strings.Split(value, ":")
		if len(parts) != 3 {
			return fmt.Errorf("overlay %q is not model:source:target", value)
		}
		parsed.Overlays = append(parsed.Overlays, runtimeconfig.VolumeOverlay{Model: parts[0], Source: parts[1], Target: parts[2]})
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		return volume.Spec{}, err
	}
	if flags.NArg() != 0 {
		return volume.Spec{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	return parsed, nil
}
