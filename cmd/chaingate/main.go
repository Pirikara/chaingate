package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/Pirikara/chaingate/internal/cache"
	"github.com/Pirikara/chaingate/internal/ecosystem"
	"github.com/Pirikara/chaingate/internal/logger"
	"github.com/Pirikara/chaingate/internal/ossfmalware"
	"github.com/Pirikara/chaingate/internal/policy"
	"github.com/Pirikara/chaingate/internal/proxy"
)

// デフォルト設定ファイルを埋め込み
//go:embed ecosystems.yaml
var defaultEcosystemsYAML []byte

var (
	// Global flags
	mode             string
	isCI             bool
	ecosystemsConfig string
	logLevel         string
	dataDir          string
	githubToken      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "chaingate [package-manager] [args...]",
		Short: "Chain Gate - Package manager security wrapper",
		Long: `Chain Gate wraps package managers and blocks malicious packages.
It uses OSSF malicious-packages database to detect threats before packages are installed.`,
		Example: `  chaingate npm install lodash
  chaingate yarn add react
  chaingate gem install rails
  chaingate --mode=strict npm install`,
		RunE: runPackageManager,
		// Allow passing through unknown flags to the package manager
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&mode, "mode", "strict", "Policy mode: strict, warn, or permissive")
	rootCmd.PersistentFlags().BoolVar(&isCI, "ci", false, "Enable CI mode (always block malware)")
	rootCmd.PersistentFlags().StringVar(&ecosystemsConfig, "ecosystems-config", "", "Path to ecosystems config file")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "Data directory for OSSF malware database (default: ~/.chaingate/feeds/ossf)")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "GitHub token for API rate limit (optional, can also use GITHUB_TOKEN env var)")

	// Subcommands
	rootCmd.AddCommand(newSelfCheckCmd())
	rootCmd.AddCommand(newPrintConfigCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runPackageManager(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no package manager specified")
	}

	// Get data directory for OSSF database
	ossfDataDir := dataDir
	if ossfDataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		ossfDataDir = filepath.Join(home, ".chaingate", "feeds", "ossf")
	}

	// Get GitHub token from flag or environment
	token := githubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	// Initialize logger
	loggerLevel := logger.LevelInfo
	switch logLevel {
	case "debug":
		loggerLevel = logger.LevelDebug
	case "warn":
		loggerLevel = logger.LevelWarn
	case "error":
		loggerLevel = logger.LevelError
	}

	log := logger.NewLogger(os.Stdout, loggerLevel)

	// Load ecosystem config (with automatic fallback to embedded default)
	ecoConfig, err := ecosystem.LoadConfig(ecosystemsConfig, defaultEcosystemsYAML)
	if err != nil {
		return fmt.Errorf("failed to load ecosystem config: %w", err)
	}

	// Initialize OSSF malware client
	ossfClient, err := ossfmalware.NewClient(ossfDataDir, token)
	if err != nil {
		return fmt.Errorf("failed to create OSSF client: %w", err)
	}
	defer ossfClient.Close()

	// Ensure OSSF database is up to date
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := ossfClient.EnsureUpdated(ctx); err != nil {
		log.Warn("ossf_sync_failed", "Failed to update OSSF database", map[string]interface{}{
			"error": err.Error(),
		})
		// Continue with local data if sync fails
	}

	// Initialize components
	detector := ecosystem.NewDetector(ecoConfig)
	threatCache := cache.NewThreatIntelCache(ossfClient)

	// Determine policy mode
	policyMode := policy.Mode(mode)
	if isCI {
		policyMode = policy.ModeStrict
	}

	// Initialize policy engine
	policyEngine := policy.NewEngine(policyMode, isCI)

	// Get cert directory
	home, _ := os.UserHomeDir()
	certDir := filepath.Join(home, ".chaingate", "certs")

	// Start MITM proxy server on random port
	proxyServer, err := proxy.NewMITMServer(proxy.Config{
		Addr:         "127.0.0.1:0", // Random port
		Detector:     detector,
		Cache:        threatCache,
		PolicyEngine: policyEngine,
		Logger:       log,
	}, certDir)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	addr, err := proxyServer.StartAndGetAddr()
	if err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	caCertPath := proxyServer.GetCACertPath()
	log.Info("proxy_started", fmt.Sprintf("Proxy listening on %s", addr), map[string]interface{}{
		"ca_cert": caCertPath,
	})

	// Prepare to stop proxy on exit
	defer proxyServer.Stop()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info("signal_received", "Shutting down", nil)
		proxyServer.Stop()
		os.Exit(130) // 128 + SIGINT
	}()

	// Execute package manager with proxy environment variables
	pmCmd := args[0]
	pmArgs := args[1:]

	command := exec.Command(pmCmd, pmArgs...)
	command.Env = os.Environ()

	// Set proxy environment variables
	proxyURL := "http://" + addr
	command.Env = append(command.Env,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		// Yarn Berry (2+) specific: only HTTPS proxy is needed
		// Yarn ignores standard HTTPS_PROXY but respects YARN_HTTPS_PROXY
		"YARN_HTTPS_PROXY="+proxyURL,
		// Add CA certificate for package managers to trust our MITM cert
		"NODE_EXTRA_CA_CERTS="+caCertPath,           // For Node.js/npm/yarn
		"SSL_CERT_FILE="+caCertPath,                 // For Python/pip and others
		"REQUESTS_CA_BUNDLE="+caCertPath,            // For Python requests library
		"CURL_CA_BUNDLE="+caCertPath,                // For curl
	)

	// Connect stdio
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	// Run the command
	log.Info("package_manager_start", fmt.Sprintf("Running: %s %v", pmCmd, pmArgs), nil)

	err = command.Run()

	// Get exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			log.Error("command_error", "Failed to run package manager", map[string]interface{}{
				"error": err.Error(),
			})
			exitCode = 1
		}
	}

	log.Info("package_manager_exit", fmt.Sprintf("Package manager exited with code %d", exitCode), nil)

	os.Exit(exitCode)
	return nil
}

func newSelfCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "self-check",
		Short: "Check Chain Gate installation and configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Chain Gate self-check")
			fmt.Println("=====================")

			// Check ecosystem config
			config, err := ecosystem.LoadConfig(ecosystemsConfig, defaultEcosystemsYAML)
			if err != nil {
				fmt.Printf("❌ Failed to load config: %v\n", err)
				return err
			}

			fmt.Printf("✅ Ecosystem config loaded: %d ecosystems\n", len(config.Ecosystems))

			// Get data directory
			ossfDataDir := dataDir
			if ossfDataDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("failed to get home directory: %w", err)
				}
				ossfDataDir = filepath.Join(home, ".chaingate", "feeds", "ossf")
			}

			// Get GitHub token
			token := githubToken
			if token == "" {
				token = os.Getenv("GITHUB_TOKEN")
			}

			// Test OSSF malicious-packages
			fmt.Println("\nTesting OSSF malicious-packages...")
			ossfClient, err := ossfmalware.NewClient(ossfDataDir, token)
			if err != nil {
				fmt.Printf("❌ Failed to create OSSF client: %v\n", err)
				return err
			}
			defer ossfClient.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			// Ensure database is up to date
			if err := ossfClient.EnsureUpdated(ctx); err != nil {
				fmt.Printf("❌ Failed to sync OSSF database: %v\n", err)
				return err
			}

			if err := ossfClient.SelfCheck(ctx); err != nil {
				fmt.Printf("❌ OSSF self-check failed: %v\n", err)
				return err
			}

			meta, _ := ossfClient.GetMetadata()
			fmt.Printf("✅ OSSF malicious-packages is accessible (%d entries, last synced: %v)\n",
				meta.EntryCount, meta.LastSync.Format(time.RFC3339))

			// Test lookup with known malware
			fmt.Println("\nTesting malware detection...")
			findings, err := ossfClient.Lookup("npm", "safe-chain-test", "1.0.0")
			if err != nil {
				fmt.Printf("❌ Lookup failed: %v\n", err)
				return err
			}

			if len(findings) > 0 {
				fmt.Printf("✅ Malware detection working (found %d malware entries for safe-chain-test@1.0.0)\n", len(findings))
				for _, f := range findings {
					fmt.Printf("   - %s: %s\n", f.ID, f.Summary)
				}
			} else {
				fmt.Println("⚠️  No malware found for test package (safe-chain-test@1.0.0)")
			}

			fmt.Println("\n✅ Chain Gate is ready to use!")
			return nil
		},
	}
}

func newPrintConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "print-config",
		Short: "Print current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Mode: %s\n", mode)
			fmt.Printf("CI: %v\n", isCI)
			fmt.Printf("Ecosystems Config: %s\n", ecosystemsConfig)
			fmt.Printf("Log Level: %s\n", logLevel)
			fmt.Printf("Data Dir: %s\n", dataDir)
			fmt.Printf("GitHub Token: %s\n", func() string {
				if githubToken != "" {
					return "[set]"
				}
				if os.Getenv("GITHUB_TOKEN") != "" {
					return "[from GITHUB_TOKEN env]"
				}
				return "[not set]"
			}())
			return nil
		},
	}
}
