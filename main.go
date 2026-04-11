package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tkukushkin/secret-box/internal/secretbox"
)

var version = "dev"

var (
	defaultBaseDir = filepath.Join(userApplicationSupportDir(), "secret-box")
	database       = secretbox.NewSecretDatabase(defaultBaseDir)
	keychain       = secretbox.SystemKeychain{}
	store          = secretbox.NewSecretStore(database, keychain)
	cache          = secretbox.NewAuthCache(database, store.AuthKey)
	ops            = &secretbox.Operations{
		Store:     store,
		Cache:     cache,
		Biometric: secretbox.SystemBiometricAuth{},
		GetCaller: secretbox.CurrentCallerIdentity,
	}
)

func userApplicationSupportDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support")
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "secret-box",
		Short: "Secure secret storage with Touch ID authentication.",
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceUsage = true

	rootCmd.AddCommand(
		versionCmd(),
		writeCmd(),
		readCmd(),
		listCmd(),
		deleteCmd(),
		resetCmd(),
		clearAuthCacheCmd(),
		execCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
}

func writeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "write <name> [value]",
		Short: "Save a secret. Value is read from stdin if not provided as argument.",
		Long: `Save a secret. Value is read from stdin if not provided as argument.

Examples:
  secret-box write my-secret "some value"
  echo -n "some value" | secret-box write my-secret
  cat file.bin | secret-box write my-binary-secret`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			var data []byte
			if len(args) > 1 {
				data = []byte(args[1])
			} else {
				var err error
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read stdin: %w", err)
				}
				if len(data) == 0 {
					return fmt.Errorf("no value provided (pass as argument or pipe to stdin)")
				}
			}
			if err := ops.WriteSecret(name, data); err != nil {
				return err
			}
			fmt.Println("Secret saved.")
			return nil
		},
	}
	return cmd
}

func readCmd() *cobra.Command {
	var once bool
	cmd := &cobra.Command{
		Use:   "read <name>",
		Short: "Read a secret (Touch ID required).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := ops.ReadSecret(args[0], once)
			if err != nil {
				return err
			}
			os.Stdout.Write(data)
			return nil
		},
	}
	cmd.Flags().BoolVar(&once, "once", false, "Authenticate with Touch ID but don't cache the session.")
	return cmd
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secret names.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			for _, name := range ops.ListSecrets() {
				fmt.Println(name)
			}
		},
	}
}

func deleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name> [names...]",
		Short: "Delete one or more secrets.",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			for _, r := range ops.DeleteSecrets(args) {
				if r.Error != nil {
					if errors.Is(r.Error, secretbox.ErrSecretNotFound) {
						fmt.Printf("%s: not found\n", r.Name)
					} else {
						fmt.Fprintf(os.Stderr, "%s: %s\n", r.Name, r.Error)
					}
				} else {
					fmt.Printf("%s: deleted\n", r.Name)
				}
			}
		},
	}
}

func resetCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete all secrets, auth cache, and the master key.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				fmt.Println("This will permanently delete all secrets and the master key.")
				fmt.Print("Type 'yes' to confirm: ")
				scanner := bufio.NewScanner(os.Stdin)
				if !scanner.Scan() || strings.ToLower(scanner.Text()) != "yes" {
					fmt.Println("Aborted.")
					os.Exit(1)
				}
			}
			if err := ops.ResetAll(); err != nil {
				return err
			}
			fmt.Println("All data has been removed.")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt.")
	return cmd
}

func clearAuthCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear-auth-cache",
		Short: "Clear the authentication cache.",
		Long:  `Clear the authentication cache. All secrets will require Touch ID on next access.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ops.ClearAuthCache(); err != nil {
				return err
			}
			fmt.Println("Auth cache cleared.")
			return nil
		},
	}
}

func execCmd() *cobra.Command {
	var once bool
	cmd := &cobra.Command{
		Use:   "exec -- command [args...]",
		Short: "Run a command with secrets injected from environment variables.",
		Long: `Run a command with secrets injected from environment variables.

Environment variables and command arguments containing $(secret-name)
references are resolved and replaced with actual secret values.

Examples:
  API_KEY='$(api-key)' secret-box exec -- myapp
  DB_PASSWORD='$(db-pass)' secret-box exec -- psql '--password=$(db-pass)'
  DB_PASSWORD='$(db-pass)' API_KEY='$(api-key)' secret-box exec -- myapp`,
		DisableFlagParsing: false,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params, err := ops.PrepareExec(os.Environ(), args, once)
			if err != nil {
				return err
			}

			for k, v := range params.Env {
				os.Setenv(k, v)
			}

			binary, err := exec.LookPath(params.Command[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: exec '%s': %s\n", params.Command[0], err)
				os.Exit(127)
			}

			if err := syscall.Exec(binary, params.Command, os.Environ()); err != nil {
				fmt.Fprintf(os.Stderr, "Error: exec '%s': %s\n", params.Command[0], err)
				os.Exit(127)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&once, "once", false, "Authenticate with Touch ID but don't cache the session.")
	return cmd
}
