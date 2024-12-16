package main

import (
	"fmt"
	"kmstool_enclave_cli_go/nsm"
	"os"
)

const (
	DEFAULT_PARENT_CID     = 3
	DEFAULT_ENTROPY_LENGTH = 1024
	DEFAULT_RSA_KEY_LENGTH = 2048
)

type Runner interface {
	Init([]string) error
	Run() error
	Name() string
}

func processSubcommands(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("you must pass a sub-command")
	}

	cmds := []Runner{
		NewGenerateRandomCommand(),
		NewDecryptCommand(),
	}

	subcommand := os.Args[1]

	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			if err := cmd.Init(os.Args[2:]); err != nil {
				return err
			}
			return cmd.Run()
		}
	}

	return fmt.Errorf("unknown subcommand: %s", subcommand)
}

func main() {
	if err := nsm.SeedEntropy(DEFAULT_ENTROPY_LENGTH); err != nil {
		fmt.Println("Failed to seed entropy:", err)
		os.Exit(1)
	}

	if err := processSubcommands(os.Args[1:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
