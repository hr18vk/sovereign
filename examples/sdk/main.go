// Command sdk-example is the canonical "how to use the Sovereign Engine" file:
// connect to a running mesh over mutual TLS and perform a state operation in
// under 50 lines of Go, importing ONLY the sovereign SDK + stdlib.
// Run: go run ./examples/sdk -addr 127.0.0.1:7432 -cert c -key k -ca ca.pem
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hr18vk/supremum/sdk/sovereign"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sdk-example: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:7432", "control port (host:port)")
	cert := flag.String("cert", "", "client cert PEM (mTLS)")
	key := flag.String("key", "", "client key PEM (mTLS)")
	ca := flag.String("ca", "", "CA PEM (trust root)")
	serverName := flag.String("server-name", "localhost", "server name to verify the node leaf against (default localhost for a dev mesh)")
	flag.Parse()
	if *cert == "" || *key == "" || *ca == "" {
		return fmt.Errorf("usage: sdk-example -addr host:port -cert c -key k -ca ca")
	}
	cli, err := sovereign.DialWithCerts(*addr, *cert, *key, *ca, *serverName)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer cli.Close()
	return cli.RunDemo()
}
