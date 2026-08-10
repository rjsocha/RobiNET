// Command robinet is all three roles in one binary: the hub on a public
// address, the tenant daemon on your own machine, and the connector inside the
// network you want to reach.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rjsocha/robinet/internal/variant"
	"github.com/rjsocha/robinet/internal/version"
	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)

	code := exitCodeFor(err, ctx.Err())
	if code == 1 {
		fmt.Fprintf(os.Stderr, "robinet: %s\n", err)
	}
	if code != 0 {
		os.Exit(code)
	}
}

// exitCodeFor decides what the process says on the way out.
//
// A requested restart arrives as SIGTERM, so it has to be recognized before
// the interrupted case: that one exits zero, and zero is what a unit saying
// Restart=on-failure treats as "stay down".
func exitCodeFor(err, ctxErr error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errRestartWanted):
		return exitRestart
	case ctxErr != nil:
		return 0
	default:
		return 1
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "robinet",
		Short: "A personal tunnel into a network you have no route to",
		Long: `robinet reaches a private network you have no route to - a Railway
environment, a docker compose network, a subnet behind someone else's NAT -
without a public address on either side and without a hosted third party.

Three roles, one binary. A hub on a public address carries enrollment requests
and runs a lighthouse per instance. A daemon on your machine holds the
certificate authority and decides who joins. A connector runs inside the
network being exposed, with no capabilities and no tun device.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		// Other roles entirely.
		newHubCmd(),
		newConnectCmd(),

		// This machine.
		newJoinCmd(),
		newSetupCmd(),
		newUpCmd(),
		newStatusCmd(),
		newReachCmd(),
		newFamilyCmd(),
		newInboundCmd(),
		newDNSCmd(),
		newRestartCmd(),

		// Its relationship to networks, and who it lets into its own.
		newInstanceCmd(),
		newMemberCmd(),

		newVersionCmd(),
	)

	// Only on a build that asked for them. Anywhere else the command does not
	// exist, so it is in no help text and in no completion.
	if variant.Cheating() {
		root.AddCommand(newCheatCmd())
	}

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print what this binary is",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			if v := variant.String(); v != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "variant %s\n", v)
			}
			return nil
		},
	}
}

func newLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// envOr lets a flag be given as an environment variable, which is how a
// connector is configured on a platform that offers nothing else.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	switch os.Getenv(name) {
	case "":
		return fallback
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
