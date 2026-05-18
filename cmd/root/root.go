// Package root defines the top-level CLI for AETHER-SNIFFER.
// All sub-commands (scan, report, plugin) are registered here.
package root

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// cfgFile holds the path to an optional config file (--config flag).
var cfgFile string

// rootCmd is the base command. Every sub-command is a child of this.
var rootCmd = &cobra.Command{
	Use:   "aether-sniffer",
	Short: "AI-aware cloud security auditor",
	Long: `
 █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗
██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗
███████║█████╗     ██║   ███████║█████╗  ██████╔╝
██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗
██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

AETHER-SNIFFER v0.1.0 — The first AI-aware cloud security auditor.
Detects exposed secrets, cloud misconfigs, and Shadow AI endpoints.
Built for enterprise. Privacy-first. All scanning runs locally.

Docs: https://github.com/Fredrickighile/aether-sniffer
`,
	// SilenceUsage prevents cobra from printing usage on every error.
	// Errors are handled cleanly by our own output layer.
	SilenceUsage: true,
}

// Execute is the single entry point called from main.go.
// It runs the root command and handles any fatal errors.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// init wires up global flags and config loading before any command runs.
func init() {
	cobra.OnInitialize(initConfig)

	// --config lets users point to a custom config file path.
	rootCmd.PersistentFlags().StringVar(
		&cfgFile, "config", "",
		"config file (default: $HOME/.aether-sniffer.yaml)",
	)

	// --output sets the global output format. Used by all sub-commands.
	rootCmd.PersistentFlags().StringP(
		"output", "o", "tui",
		"output format: tui | json | pdf",
	)

	// --verbose enables debug-level logging across all modules.
	rootCmd.PersistentFlags().BoolP(
		"verbose", "v", false,
		"enable verbose/debug output",
	)

	// Bind cobra flags to viper so config file values are also respected.
	_ = viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig loads the config file and environment variables.
// Environment variables prefixed with AETHER_ override config file values.
// Example: AETHER_OUTPUT=json overrides --output flag default.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not determine home directory:", err)
		} else {
			viper.AddConfigPath(home)
		}
		viper.SetConfigName(".aether-sniffer")
		viper.SetConfigType("yaml")
	}

	// AETHER_OUTPUT, AETHER_VERBOSE, etc. are automatically picked up.
	viper.SetEnvPrefix("AETHER")
	viper.AutomaticEnv()

	// Config file is optional. Missing file is not an error.
	if err := viper.ReadInConfig(); err == nil {
		if viper.GetBool("verbose") {
			fmt.Fprintln(os.Stderr, "using config file:", viper.ConfigFileUsed())
		}
	}
}