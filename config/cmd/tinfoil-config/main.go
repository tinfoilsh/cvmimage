package main

import (
	"flag"
	"fmt"
	"os"

	tinfoilconfig "github.com/tinfoilsh/cvmimage/config"
)

func main() {
	hostDebug := flag.Bool("host-debug", false, "validate YAML after trusted tinfoild debug injection")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [--host-debug] CONFIG.yml\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}
	options := tinfoilconfig.Options{}
	if *hostDebug {
		options.Mode = tinfoilconfig.HostDebugMode
	}
	if err := tinfoilconfig.ValidateBytes(data, options); err != nil {
		fmt.Fprintf(os.Stderr, "invalid tinfoil config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("valid tinfoil config: %s\n", flag.Arg(0))
}
