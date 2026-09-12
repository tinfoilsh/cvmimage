package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "--format" {
		if err := runFormatter(os.Args); err != nil {
			log.Fatal(err)
		}
		return
	}
	secrets := flag.Int("secrets-fd", -1, "sealed storage secret descriptor")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	syscall.Umask(0077)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *secrets); err != nil {
		log.Fatal(err)
	}
}
