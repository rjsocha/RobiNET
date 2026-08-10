package main

// The cheats. Each one exists because another program does something that
// cannot be argued with, and each one is a hijacked address or a route that
// leads nowhere. They live in their own file so that the day the behaviour
// changes, the whole file goes.
//
// The command tree only exists on a build whose variant asked for it. Nobody
// else gets it in their help, in their completion, or on their socket.

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/spf13/cobra"
)

func newCheatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cheat",
		Short: "Work around what another program insists on",
		Long: `cheat holds the workarounds for behaviour that belongs to somebody else's
program, where the only way through is to tell it what it wants to hear.

Each one has a cost, and the cost is written on the command that turns it on.`,
	}

	cmd.AddCommand(newCheatChromiumCmd())

	return cmd
}

func newCheatChromiumCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chromium",
		Short: "Chrome, Chromium, and everything built on them",
	}

	cmd.AddCommand(newCheatChromiumProbeRouteCmd())

	return cmd
}

// newCheatChromiumProbeRouteCmd turns the IPv6 probe route on and off.
//
// Chromium decides whether to ask for AAAA at all by connecting a UDP socket
// to Google's public resolver. A connected UDP socket sends nothing, so the
// test is really "does the kernel have a route and a source address", and a
// route into the overlay passes it. Nothing else has to be true: an IPv6 only
// network behind a connector then resolves and loads in the browser, which it
// does not without this however well the tunnel works.
func newCheatChromiumProbeRouteCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   tenant.CheatChromiumProbeRoute + " [on|off]",
		Short: "Tell Chromium this machine has global IPv6",
		Long: `Chromium asks whether IPv6 works by connecting a UDP socket to Google's
public resolver, and stops requesting AAAA records when that fails. Nothing is
sent, so a route that leads nowhere answers the question.

The cost: while this is on, 2001:4860:4860::8888 belongs to the overlay. A /128
beats any other route by prefix length, so that resolver is unreachable over
IPv6 from this machine, and it stays that way even if real IPv6 arrives.

Only takes effect on a connection that has an IPv6 address of its own.`,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"on", "off"},
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			if len(args) == 0 {
				var status tenant.Status
				if err := newControl(path).do(cmd.Context(), http.MethodGet, "/status", nil, &status); err != nil {
					return err
				}
				fmt.Println(onOff(slices.Contains(status.Cheats, cheatRef())))
				return nil
			}

			var out struct {
				On bool `json:"on"`
			}
			req := tenant.CheatRequest{
				Vendor: tenant.CheatChromium,
				Name:   tenant.CheatChromiumProbeRoute,
				On:     args[0] == "on",
			}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/cheat", req, &out); err != nil {
				return err
			}

			fmt.Printf("%s: %s\n", chromiumProbeAddress, onOff(out.On))
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

// chromiumProbeAddress is repeated here rather than exported, because what the
// command prints is for a person to recognize and not a value anything reads.
const chromiumProbeAddress = "2001:4860:4860::8888/128"

func cheatRef() string {
	return tenant.CheatChromium + "/" + tenant.CheatChromiumProbeRoute
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
