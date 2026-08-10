package main

import (
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/spf13/cobra"
)

// newReachCmd answers the question somebody actually has: what can I get to
// from here, and what do I call it.
//
// The pieces were already visible - prefixes in status, domains in member
// list, name spaces in dns - and nowhere were they in one place, which is
// where the question is asked.
func newReachCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "reach",
		Short: "What this machine can reach, and what to call it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var entries []tenant.Reach
			if err := newControl(path).do(cmd.Context(), http.MethodGet, "/reach", nil, &entries); err != nil {
				return err
			}

			if len(entries) == 0 {
				fmt.Println("nothing: no connector in any instance this machine belongs to carries a network")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "INSTANCE\tNETWORK\tCARRIED BY\tNAMES")
			for _, e := range entries {
				names := e.Names
				switch {
				case names == "":
					names = "-"
				case !e.Installed:
					names += "  (not installed)"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Instance, e.Network, dashIfEmpty(e.Carrier), names)
			}
			w.Flush()

			// Only when it would help: a name space that resolves needs no
			// explanation, and one that does not needs the command.
			for _, e := range entries {
				if e.Names != "" && !e.Installed {
					fmt.Println("\n  robinet dns install   to resolve those names on this machine")
					break
				}
			}

			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}
