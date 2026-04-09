package main

import (
	"bufio"
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

var (
	defaultBaseDir = filepath.Join(userApplicationSupportDir(), "secret-box")
	database       = secretbox.NewSecretDatabase(defaultBaseDir)
	keychain       = secretbox.SystemKeychain{}
	store          = secretbox.NewSecretStore(database, keychain)
	cache          = secretbox.NewAuthCache(database, store.AuthKey)
	biometric      secretbox.BiometricAuth = secretbox.SystemBiometricAuth{}
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
		writeCmd(),
		readCmd(),
		listCmd(),
		deleteCmd(),
		resetCmd(),
		execCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
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
			if err := store.Write(name, data); err != nil {
				return err
			}
			cache.Invalidate(name)
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
			name := args[0]

			if !store.Exists(name) {
				fmt.Fprintln(os.Stderr, "Error: secret not found")
				os.Exit(1)
			}

			caller := secretbox.CurrentCallerIdentity()

			if !cache.IsValid(caller.ID, name) {
				reason := fmt.Sprintf(`"%s" wants to access "%s"`, caller.DisplayName, name)
				if err := biometric.Authenticate(reason); err != nil {
					return err
				}
				if !once {
					cache.Update(caller.ID, name)
				}
			}

			data, err := store.Read(name)
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
			for _, name := range store.List() {
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
			for _, name := range args {
				if !store.Exists(name) {
					fmt.Printf("%s: not found\n", name)
					continue
				}
				if err := store.Delete(name); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s\n", name, err)
					continue
				}
				cache.Invalidate(name)
				fmt.Printf("%s: deleted\n", name)
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

			if err := store.ResetAll(); err != nil {
				return err
			}
			fmt.Println("All data has been removed.")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt.")
	return cmd
}

func execCmd() *cobra.Command {
	var envMappings []string
	cmd := &cobra.Command{
		Use:   "exec -e ENV_VAR=secret-name [...] -- command [args...]",
		Short: "Run a command with secrets in environment variables.",
		Long: `Run a command with secrets in environment variables.

Secrets are set as environment variables. Use $(VAR) in command
arguments to substitute the secret value inline.

Examples:
  secret-box exec -e DB_PASSWORD=db-pass -- psql
  secret-box exec -e DB_PASSWORD=db-pass -- psql '--password=$(DB_PASSWORD)'
  secret-box exec -e DB_PASSWORD=db-pass -e API_KEY=api-key -- myapp`,
		DisableFlagParsing: false,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate env mappings
			if len(envMappings) == 0 {
				return fmt.Errorf("at least one -e/--env mapping is required")
			}

			type mapping struct {
				varName    string
				secretName string
			}
			var mappings []mapping
			for _, entry := range envMappings {
				parts := strings.SplitN(entry, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid env mapping '%s': expected format ENV_VAR=secret-name", entry)
				}
				mappings = append(mappings, mapping{parts[0], parts[1]})
			}

			// Verify all secrets exist
			for _, m := range mappings {
				if !store.Exists(m.secretName) {
					fmt.Fprintf(os.Stderr, "Error: secret '%s' not found\n", m.secretName)
					os.Exit(1)
				}
			}

			// Check auth cache, collect uncached secrets
			caller := secretbox.CurrentCallerIdentity()
			var uncachedSecrets []string
			for _, m := range mappings {
				if !cache.IsValid(caller.ID, m.secretName) {
					uncachedSecrets = append(uncachedSecrets, m.secretName)
				}
			}

			// Single Touch ID prompt for all uncached secrets
			if len(uncachedSecrets) > 0 {
				quoted := make([]string, len(uncachedSecrets))
				for i, s := range uncachedSecrets {
					quoted[i] = fmt.Sprintf(`"%s"`, s)
				}
				reason := fmt.Sprintf(`"%s" wants to access %s`, caller.DisplayName, strings.Join(quoted, ", "))
				if err := biometric.Authenticate(reason); err != nil {
					return err
				}
				for _, secretName := range uncachedSecrets {
					cache.Update(caller.ID, secretName)
				}
			}

			// Read secrets and set env vars
			resolved := make(map[string]string)
			for _, m := range mappings {
				data, err := store.Read(m.secretName)
				if err != nil {
					return err
				}
				value := string(data)
				// Check for valid UTF-8 (Go strings are UTF-8 by default, but raw bytes might not be)
				for _, b := range data {
					if b == 0 {
						fmt.Fprintf(os.Stderr, "Error: secret '%s' is not valid UTF-8\n", m.secretName)
						os.Exit(1)
					}
				}
				resolved[m.varName] = value
				os.Setenv(m.varName, value)
			}

			// Substitute $(VAR) in command arguments
			expandedCommand := secretbox.ExpandVariables(args, resolved)

			// execvp
			binary, err := exec.LookPath(expandedCommand[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: exec '%s': %s\n", args[0], err)
				os.Exit(127)
			}

			if err := syscall.Exec(binary, expandedCommand, os.Environ()); err != nil {
				fmt.Fprintf(os.Stderr, "Error: exec '%s': %s\n", args[0], err)
				os.Exit(127)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&envMappings, "env", "e", nil, "Map secret to env var (format: ENV_VAR=secret-name).")
	return cmd
}
