// Copyright (c) 2026 Parallel Hours LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"

	sealchain "github.com/parallelhours/sealchain"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sealcheck <subcommand> [args]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  verify <path>              Verify the integrity of an audit log file")
		fmt.Fprintln(os.Stderr, "  verify-chain <dir> <base>  Verify cross-log rotation chain")
		return 2
	}

	switch args[0] {
	case "verify":
		return cmdVerify(args[1:])
	case "verify-chain":
		return cmdVerifyChain(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n", args[0])
		fmt.Fprintln(os.Stderr, "Run 'sealcheck' with no arguments for usage.")
		return 2
	}
}

func cmdVerify(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sealcheck verify <path>")
		return 2
	}
	path := args[0]

	l := sealchain.NewLog(path)

	entries, err := l.Entries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading log: %v\n", err)
		return 1
	}

	if err := l.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		return 1
	}

	fmt.Printf("OK: %d entries verified\n", len(entries))
	return 0
}

func cmdVerifyChain(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: sealcheck verify-chain <log-dir> <base-name>")
		return 2
	}
	if err := sealchain.VerifyChain(args[0], args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "verify-chain failed: %v\n", err)
		return 1
	}
	fmt.Println("verify-chain: chain valid")
	return 0
}
