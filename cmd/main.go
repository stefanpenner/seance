package main

import (
	"fmt"
	"os"

	"seance"
)

func main() {
	if len(os.Args) < 2 {
		seance.Run()
		return
	}

	switch os.Args[1] {
	case "daemon":
		seance.RunDaemon()
	case "attach":
		id := ""
		if len(os.Args) > 2 {
			id = os.Args[2]
		}
		seance.RunAttach(id)
	case "kill":
		id := ""
		if len(os.Args) > 2 {
			id = os.Args[2]
		}
		seance.RunKill(id)
	case "list", "ls":
		seance.RunList()
	case "--help", "-h", "help":
		printUsage()
	default:
		// If first arg starts with -, assume flags for Run() (e.g. --no-password)
		if len(os.Args[1]) > 0 && os.Args[1][0] == '-' {
			seance.Run()
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: seance [command] [flags]

Commands:
  (default)    Start server with TUI
  daemon       Start server without TUI (background mode)
  attach [id]  Attach to a session on a running daemon
  kill [id]    Kill a session on a running daemon
  list         List sessions on a running daemon
  help         Show this help

Flags:
  --no-password  Disable authentication
  --insecure     Skip TLS verification (for attach/list with self-signed certs)

Environment:
  SEANCE_PASSWORD    Server password (required unless --no-password)
  SEANCE_ADDR        Listen address (default :8443)
  SEANCE_TLS_CERT    TLS certificate file
  SEANCE_TLS_KEY     TLS key file
  SEANCE_SHELL       Default shell
  SEANCE_BUFFER_SIZE Ring buffer size per session`)
}
