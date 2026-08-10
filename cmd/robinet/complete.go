package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/spf13/cobra"
)

// Completion asks the running daemon what the next word could be, because it is
// the only thing that knows: instances live on a hub and requests arrive while
// somebody is typing.
//
// Everything here fails silent. A shell that printed an error where a list was
// expected would be worse than one that completed nothing, and a daemon that is
// not running is the ordinary case for somebody exploring the help.
const completionTimeout = 2 * time.Second

// completing runs fn against the daemon with a deadline the shell can live
// with.
func completing[T any](cmd *cobra.Command, socket, path string, out *T) bool {
	sock, err := socketPath(socket)
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()

	return newControl(sock).do(ctx, http.MethodGet, path, nil, out) == nil
}

// completeInstances offers the instances this machine can see, by name, with
// what each one is beside it.
//
// Identifiers are offered only for an instance with no name to offer, since a
// name is the thing worth typing and both resolve.
func completeInstances(socket string, mine bool) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var instances []hub.InstanceSummary
		if !completing(cmd, socket, "/list", &instances) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var out []string
		for _, i := range instances {
			// attach wants the ones this machine is not in; detach and show
			// want the ones it is.
			if mine != (i.Role != "") {
				continue
			}

			name := i.Name
			if name == "" {
				name = i.ID
			}
			out = append(out, fmt.Sprintf("%s\t%s", name, describeInstance(i)))
		}

		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

func describeInstance(i hub.InstanceSummary) string {
	owner := i.Owner
	if i.OwnerMachine != "" {
		owner = fmt.Sprintf("%s (%s)", i.Owner, i.OwnerMachine)
	}
	if i.Role == "" {
		return "owned by " + owner
	}
	return fmt.Sprintf("%s, owned by %s", i.Role, owner)
}

// completePending offers what is waiting for a decision, described well enough
// to decide from the completion itself.
func completePending(socket string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var pending []tenant.PendingEntry
		if !completing(cmd, socket, "/pending", &pending) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var out []string
		for _, p := range pending {
			out = append(out, fmt.Sprintf("%s\t%s %s in %s",
				short(p.Record.ID, 8), p.Record.Kind, applicantName(p.Record.Request), p.Instance))
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeMembers offers who is already inside, which is what ban takes.
func completeMembers(socket string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var members []tenant.MemberEntry
		if !completing(cmd, socket, "/members", &members) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}

		var out []string
		for _, m := range members {
			if m.Member == nil || m.Member.Kind == hub.KindOwner {
				continue
			}

			// Ban takes a name or a fingerprint. The name is what a person
			// reads, so that is what is offered.
			name := m.Member.Name
			if name == "" {
				name = short(m.Member.Fingerprint, 16)
			}
			out = append(out, fmt.Sprintf("%s\t%s in %s at %s",
				name, m.Member.Kind, m.Instance, m.Member.Address))
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}
