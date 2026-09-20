package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kotaru34/tethys-sentinel/internal/remotewrapper"
)

func main() {
	jobID := flag.String("job", "", "execution job id")
	binding := flag.String("binding", "", "execution command binding")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("unexpected helper arguments")
	}
	if os.Geteuid() != 0 {
		fatal("must run with effective uid 0")
	}
	if err := remotewrapper.ConsumeExecution("", *jobID, *binding, time.Now()); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "tethys-sentinel-consume:", message)
	os.Exit(1)
}
