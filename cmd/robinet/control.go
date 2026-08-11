package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/tenant"
	"github.com/rjsocha/robinet/internal/version"
	"github.com/spf13/cobra"
)

// control talks to the tenant daemon over its unix socket.
type control struct {
	client *http.Client
	path   string

	// anyVersion skips the contract check, for the one command whose whole
	// purpose is to replace a daemon that fails it.
	anyVersion bool
}

func newControl(path string) *control {
	return &control{path: path, client: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}}
}

func (c *control) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, "http://robinet"+path, body)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.unreachable(err)
	}
	defer resp.Body.Close()

	if !c.anyVersion {
		if err := checkVersion(resp.Header.Get(tenant.VersionHeader)); err != nil {
			return err
		}
	}

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// unreachable says why the daemon did not answer, in terms of the daemon.
//
// What net/http hands back names a url that is a placeholder - the transport
// dials a socket and never resolves a host - so it is unwrapped down to the
// syscall, which is the only part that means anything here.
func (c *control) unreachable(err error) error {
	if e := (*url.Error)(nil); errors.As(err, &e) {
		err = e.Err
	}
	// And once more, because a dial error repeats the path this message is
	// about to print anyway.
	if e := (*net.OpError)(nil); errors.As(err, &e) {
		err = e.Err
	}

	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err

	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the daemon is not running: robinet setup")

	// The socket outlived the process that made it, which is what a killed
	// daemon leaves behind. The same answer, said so that somebody who looks
	// and finds the file there is not left doubting the message.
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("the daemon is not running, though %s is still there: robinet setup", c.path)

	// The socket belongs to whoever registered this machine, and is readable
	// by nobody else. Root included, in spirit: it is not a permission to be
	// borrowed, it is whose daemon this is.
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s belongs to the user who registered this machine, and this is not them", c.path)
	}

	return fmt.Errorf("could not reach the daemon on %s: %w", c.path, err)
}

// checkVersion refuses to talk to a daemon from a different build.
//
// Not a compatibility judgement: the two halves are one program, so the only
// combination anybody tested is the one where they match. A daemon from before
// this header existed sends nothing at all, which is the common case right
// after an upgrade and gets the same answer.
func checkVersion(header string) error {
	if header == version.String() {
		return nil
	}

	return fmt.Errorf("the daemon is running %s and this command is %s: robinet restart",
		headerOrUnknown(header), version.String())
}

func headerOrUnknown(header string) string {
	if header == "" {
		return "an older build"
	}
	return header
}

func addSocketFlag(cmd *cobra.Command, target *string) {
	cmd.Flags().StringVar(target, "socket", "", "control socket (default is /run/robinet/robinet.sock)")
}

func defaultMachineName() string {
	if host, err := os.Hostname(); err == nil && host != "" {
		if u, err := user.Current(); err == nil && u.Username != "" {
			return u.Username + "@" + host
		}
		return host
	}
	return "robinet"
}

func newStatusCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what this machine is connected to and what is waiting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var status tenant.Status
			if err := newControl(path).do(cmd.Context(), http.MethodGet, "/status", nil, &status); err != nil {
				return err
			}

			fmt.Printf("hub        %s\n", status.Hub)
			fmt.Printf("machine    %s (binder %s)\n", status.Name, status.Binder)

			// The daemon does the work, so its build is the one that matters.
			// Different builds can still speak the same contract, so this is
			// information rather than a refusal.
			if status.Families != "" && status.Families != tenant.FamiliesBoth {
				fmt.Printf("routes     %s only, by local choice\n", status.Families)
			}
			if status.Inbound != "" && status.Inbound != tenant.InboundPing {
				fmt.Printf("inbound    %s\n", status.Inbound)
			}

			if status.Version != "" && status.Version != version.String() {
				fmt.Printf("daemon     %s, this command is %s\n", status.Version, version.String())
			}

			if len(status.Connections) > 0 {
				fmt.Println("\nconnections")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				// The second address column only exists when something has
				// one: a hub with no IPv6 pool would otherwise print a column
				// of dashes for every member of every instance.
				dual := false
				for _, c := range status.Connections {
					dual = dual || c.Address6.IsValid()
				}

				if dual {
					fmt.Fprintln(w, "  INSTANCE\tROLE\tADDRESS\tADDRESS6\tDEVICE\tSTATE\tROUTES")
				} else {
					fmt.Fprintln(w, "  INSTANCE\tROLE\tADDRESS\tDEVICE\tSTATE\tROUTES")
				}
				for _, c := range status.Connections {
					if dual {
						fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
							c.Instance, c.Role, addrOrDash(c.Address), addrOrDash(c.Address6),
							c.Device, connState(c), routeList(c.Routes))
						continue
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n",
						c.Instance, c.Role, addrOrDash(c.Address), c.Device, connState(c), routeList(c.Routes))
				}
				w.Flush()

				// Twice, because it is copied into two different kinds of
				// field: one takes a whole assignment, the other takes a name
				// and a value in separate boxes.
				for _, c := range status.Connections {
					if c.Endpoint == "" {
						continue
					}
					fmt.Printf("\n  connectors for %s\n", c.Instance)
					fmt.Printf("    ROBINET_ENDPOINT=%s\n", c.Endpoint)
					fmt.Printf("    ROBINET_ENDPOINT  %s\n", c.Endpoint)
				}
			}

			if len(status.Pending) > 0 {
				fmt.Println("\nwaiting for a decision")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  ID\tINSTANCE\tKIND\tNAME\tADDRESS\tROUTES\tFROM")
				for _, p := range status.Pending {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						p.Record.ID[:8], p.Instance, p.Record.Kind, p.Record.Request.Name,
						p.Address, prefixes(p.Record.Request.Routes), p.Record.SourceAddr)
				}
				w.Flush()
				fmt.Println("\n  robinet member approve <id>   to admit one")
			}

			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

func newListCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the instances this machine can see on its hub",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var instances []hub.InstanceSummary
			if err := newControl(path).do(cmd.Context(), http.MethodGet, "/list", nil, &instances); err != nil {
				return err
			}

			if len(instances) == 0 {
				fmt.Println("nothing here yet: create one, or ask an owner for the name of theirs")
				return nil
			}

			var (
				strangers []hub.InstanceSummary
				stopped   []string
			)

			// The second address column only when something has one, the same
			// as everywhere else it appears.
			dual := false
			for _, i := range instances {
				dual = dual || i.Address6.IsValid()
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			if dual {
				fmt.Fprintln(w, "NAME\tOWNER\tYOU\tADDRESS\tADDRESS6\tPENDING\tMEMBERS")
			} else {
				fmt.Fprintln(w, "NAME\tOWNER\tYOU\tADDRESS\tPENDING\tMEMBERS")
			}
			for _, i := range instances {
				owner := i.Owner
				if i.OwnerMachine != "" {
					owner = fmt.Sprintf("%s (%s)", i.Owner, i.OwnerMachine)
				}
				// Reading your own name and comparing it with who you are is
				// work this can do for you.
				if i.Role == hub.KindOwner {
					owner = "you"
				}

				// Said as a state rather than a role: a dash in a column
				// called ROLE reads as missing data rather than as the answer
				// it is.
				you := "member"
				switch i.Role {
				case "":
					you = "not joined"
					strangers = append(strangers, i)
				case hub.KindOwner, hub.KindConnector:
					you = i.Role
				}

				members := "-"
				if i.Members > 0 {
					members = fmt.Sprintf("%d", i.Members)
				}

				if !i.Running {
					stopped = append(stopped, i.Name)
				}

				if dual {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						i.Name, owner, you, addrOrDash(i.Address), addrOrDash(i.Address6),
						pendingOrDash(i.Pending), members)
					continue
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					i.Name, owner, you, addrOrDash(i.Address), pendingOrDash(i.Pending), members)
			}
			w.Flush()

			// A column of trues says nothing, and false is the only thing
			// anybody needs to be told.
			for _, name := range stopped {
				fmt.Printf("\n  %s: its lighthouse is not running on the hub\n", name)
			}

			// Said per instance, because the two cases read nothing alike:
			// one is somebody else's, and the other is your own from a
			// machine that does not hold its key.
			if len(strangers) > 0 {
				fmt.Println()
			}
			for _, i := range strangers {
				if i.Yours {
					where := i.OwnerMachine
					if where == "" {
						where = "another machine"
					}
					fmt.Printf("  %s is yours, but its authority is on %s: attach here, approve on %s\n",
						i.Name, where, where)
					continue
				}

				fmt.Printf("  %s belongs to %s: attach, and they approve it\n", i.Name, i.Owner)
			}

			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

func newAttachCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "attach <instance>",
		Short: "Ask to be let into an instance somebody else owns",
		Long: `attach asks the owner of an instance to admit this machine.

The request appears in their status with your name and your binder, because the
hub vouches for who you are. Once they approve, the tunnel comes up on its own
and you see every route that instance carries.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, false),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			err = newControl(path).do(cmd.Context(), http.MethodPost, "/connect",
				tenant.ConnectRequest{Instance: args[0]}, nil)
			if err != nil {
				return err
			}

			fmt.Printf("asked to join %s, waiting for the owner\n", args[0])
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

func newDetachCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:               "detach <instance>",
		Short:             "Leave an instance and drop its routes",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeInstances(socket, true),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			err = newControl(path).do(cmd.Context(), http.MethodPost, "/disconnect",
				tenant.ConnectRequest{Instance: args[0]}, nil)
			if err != nil {
				return err
			}

			fmt.Printf("left %s\n", args[0])
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

// newFamilyCmd is the one thing about the mesh a member decides for itself.
//
// It changes nothing anybody else can see: the certificate carries both
// families whatever this says, and the hub is never told. It decides which
// routes go on this machine's device, which is the only part that is this
// machine's business.
func newFamilyCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:       "family [both|ipv4|ipv6]",
		Short:     "Which address families this machine installs routes for",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{tenant.FamiliesBoth, tenant.FamiliesIPv4, tenant.FamiliesIPv6},
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
				fmt.Println(status.Families)
				return nil
			}

			var out struct {
				Families string `json:"families"`
			}
			req := tenant.FamiliesRequest{Families: args[0]}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/families", req, &out); err != nil {
				return err
			}

			fmt.Printf("installing %s routes\n", out.Families)
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

// newInboundCmd is the other thing a member decides for itself.
//
// Nothing about it belongs to the instance: the hub is never told, no owner
// can set it on somebody else's behalf, and the machine that carries the
// consequence is the one that chooses.
func newInboundCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "inbound [ping|open|none]",
		Short: "What members of an instance may reach on this machine",
		Long: `inbound is what the other members of an instance may reach here.

ping by default. Joining an instance to reach a network somebody exposed is not
an offer to be reached back, and everyone else in that instance is a stranger
who was admitted by the same owner. Echo requests are answered because that is
how people check a tunnel is alive, and they give nothing away.

open is for a machine that means to offer something. none answers nothing.`,
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{tenant.InboundPing, tenant.InboundOpen, tenant.InboundNone},
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
				fmt.Println(status.Inbound)
				return nil
			}

			var out struct {
				Inbound string `json:"inbound"`
			}
			req := tenant.InboundRequest{Inbound: args[0]}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/inbound", req, &out); err != nil {
				return err
			}

			fmt.Printf("members may reach: %s\n", out.Inbound)
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

// newRestartCmd exists because the daemon does the work and an upgrade leaves
// it running the old binary. Asking it over its own socket keeps the user out
// of sudo and out of systemctl for something that is robinet's own business.
func newRestartCmd() *cobra.Command {
	var socket string

	cmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the daemon, so it runs the binary that is installed now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			// A daemon old enough to fail the contract check is exactly the one
			// worth restarting, so this call does not make the check.
			c := newControl(path)
			c.anyVersion = true

			var was struct {
				Version string `json:"version"`
			}
			if err := c.do(cmd.Context(), http.MethodPost, "/restart", nil, &was); err != nil {
				if strings.Contains(err.Error(), "404") {
					return fmt.Errorf("this daemon is too old to restart itself: sudo systemctl restart robinet")
				}
				return err
			}

			fmt.Printf("daemon %s is stopping, its supervisor starts %s\n", was.Version, version.String())
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	return cmd
}

func newApproveCmd() *cobra.Command {
	var (
		socket   string
		only     []string
		noDomain bool
		name     string
	)

	cmd := &cobra.Command{
		Use:               "approve <id>",
		Short:             "Admit a pending connector or tenant",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completePending(socket),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			req := tenant.ApproveRequest{ID: args[0], NoDomain: noDomain, Name: name}
			for _, raw := range only {
				p, err := netip.ParsePrefix(strings.TrimSpace(raw))
				if err != nil {
					return fmt.Errorf("bad prefix %q: %w", raw, err)
				}
				req.Routes = append(req.Routes, p)
			}

			var entry tenant.PendingEntry
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/approve", req, &entry); err != nil {
				return err
			}

			// Both addresses: on a network with no IPv4 the second one is the
			// only one anybody will use, and it is not derivable from the
			// first by looking at it.
			at := entry.Address.String()
			if entry.Record.OverlayAddress6.IsValid() {
				at += " and " + entry.Record.OverlayAddress6.String()
			}
			fmt.Printf("admitted %s to %s at %s\n",
				applicantName(entry.Record.Request), entry.Instance, at)
			if len(entry.Routes) > 0 {
				fmt.Printf("carrying %s\n", prefixes(entry.Routes))
			}
			if entry.Domain != "" {
				fmt.Printf("resolving %s\n", entry.Domain)
			}
			for _, d := range entry.Dropped {
				fmt.Printf("not carrying %s: this instance has no address of that family\n", d)
			}
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().StringSliceVar(&only, "routes", nil, "prefixes to accept from a connector, defaults to everything announced")
	cmd.Flags().BoolVar(&noDomain, "no-domain", false, "refuse the zone it announced; it carries routes and no names")
	cmd.Flags().StringVar(&name, "name", "", "what to call it, which is also its name in DNS")

	return cmd
}

func newDecisionCmd(action, short string) *cobra.Command {
	var (
		socket string
		reason string
	)

	cmd := &cobra.Command{
		Use:               action + " <id>",
		Short:             short,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completePending(socket),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			req := tenant.DecisionRequest{ID: args[0], Reason: reason}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/"+action, req, nil); err != nil {
				return err
			}

			fmt.Printf("%s %s\n", action, args[0])
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	if action == "reject" {
		cmd.Flags().StringVar(&reason, "reason", "", "shown to whoever asked")
	}

	return cmd
}

// newRemoveMemberCmd is the end of the line for a member, and it only follows
// a ban.
func newRemoveMemberCmd() *cobra.Command {
	var socket, instance string

	cmd := &cobra.Command{
		Use:   "remove <name or fingerprint>",
		Short: "Forget a banned member and burn its credentials",
		Long: `remove forgets a member: its record, the decisions taken about it, its
address, and the request it arrived with. Its name and its address are free
again for whatever comes next.

Only a banned member can be removed. A certificate cannot be revoked, so a
member that is not banned still holds a good one for the address this frees,
and the next member admitted would be handed an address something is already
using. Ban it first, and the ban is what keeps it out.

Its key and its certificate are burned on the way out: the certificate stays
on every blocklist, and an enrollment from that key is refused by the hub
without being put in front of you. Nothing takes either off again, so the same
machine comes back only with a new key.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeMembers(socket),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			var entry tenant.MemberEntry
			req := tenant.BanRequest{Member: args[0], Instance: instance}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/member/remove", req, &entry); err != nil {
				return err
			}

			fmt.Printf("removed %s from %s, its credentials are burned, and %s is free again\n",
				dashIfEmpty(entry.Member.Name), entry.Instance, entry.Member.Address)
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	addMemberInstanceFlag(cmd, &socket, &instance)
	return cmd
}

// addMemberInstanceFlag settles which instance is meant. A member's name is
// unique inside one and nowhere else, so two instances this machine owns can
// both hold a "railway", and a command given only the name is refused rather
// than guessing.
func addMemberInstanceFlag(cmd *cobra.Command, socket, instance *string) {
	cmd.Flags().StringVar(instance, "instance", "", "which instance the member is in, when the name means more than one")
	_ = cmd.RegisterFlagCompletionFunc("instance", completeInstances(*socket, true))
}

func newBanCmd() *cobra.Command {
	var socket, note, instance string

	cmd := &cobra.Command{
		Use:   "ban <name or fingerprint>",
		Short: "Blocklist a member and drop its routes",
		Long: `ban keeps a member out without forgetting it. Its certificate goes onto
every blocklist and its routes leave the table, but the member stays, holding
its name and its address, and unban lets it back in.

The note is kept with the decision and it is the only place the reason for it
survives.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeMembers(socket),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			req := tenant.BanRequest{Member: args[0], Note: note, Instance: instance}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/ban", req, nil); err != nil {
				return err
			}

			fmt.Printf("banned %s, its certificate is blocklisted and its routes are gone\n", args[0])
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().StringVar(&note, "note", "", "why, kept with the decision")
	addMemberInstanceFlag(cmd, &socket, &instance)
	return cmd
}

func newUnbanCmd() *cobra.Command {
	var socket, note, instance string

	cmd := &cobra.Command{
		Use:   "unban <name or fingerprint>",
		Short: "Let a banned member back in",
		Long: `unban takes a member's certificate off every blocklist and puts its routes
back in the table.

Nothing is reissued: the certificate was never revoked, because it cannot be,
and it starts working again the moment everybody stops refusing it.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeMembers(socket),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := socketPath(socket)
			if err != nil {
				return err
			}

			req := tenant.BanRequest{Member: args[0], Note: note, Instance: instance}
			if err := newControl(path).do(cmd.Context(), http.MethodPost, "/unban", req, nil); err != nil {
				return err
			}

			fmt.Printf("unbanned %s, its certificate works again and its routes are back\n", args[0])
			return nil
		},
	}

	addSocketFlag(cmd, &socket)
	cmd.Flags().StringVar(&note, "note", "", "why, kept with the decision")
	addMemberInstanceFlag(cmd, &socket, &instance)
	return cmd
}

func connState(c tenant.ConnectionStatus) string {
	switch {
	case c.Running:
		return "up"
	case c.Waiting:
		return "waiting"
	default:
		return "down"
	}
}

func pendingOrDash(n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

func addrOrDash(p netip.Prefix) string {
	if !p.IsValid() {
		return "-"
	}
	return p.String()
}

func routeList(routes []hub.Route) string {
	if len(routes) == 0 {
		return "-"
	}

	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Prefix.String())
	}
	return strings.Join(out, ",")
}

// willBeCalled is the name approving would give it.
func willBeCalled(p tenant.PendingEntry) string {
	if p.WillBeCalled != "" {
		return p.WillBeCalled
	}
	return applicantName(p.Record.Request)
}

// applicantName is what to call a request in a table. A connector without a
// --name is not anonymous: it reports its hostname, which on a platform is the
// deployment or the container.
func applicantName(r enroll.Request) string {
	if r.Name != "" {
		return r.Name
	}
	if host := r.Hints["hostname"]; host != "" {
		return host
	}
	return "-"
}

// describe prints what is known about a request beyond what fits in a row.
// This is everything the decision can be based on, and none of it is trusted:
// the applicant chose all of it except the source address.
func describe(p tenant.PendingEntry) {
	fmt.Printf("\n  %s  %s in %s\n", short(p.Record.ID, 8), p.Record.Kind, p.Instance)

	// What it will be called, because that is the name space it answers under
	// and it is part of what is being decided rather than a consequence of it.
	if name := willBeCalled(p); name != "-" {
		fmt.Printf("    called       %s.%s.%s\n", name, p.Instance, tenant.Suffix)
	}

	fmt.Printf("    address      %s\n", p.Address)
	if p.Record.OverlayAddress6.IsValid() {
		fmt.Printf("    address6     %s\n", p.Record.OverlayAddress6)
	}
	fmt.Printf("    routes       %s\n", prefixes(p.Record.Request.Routes))
	if p.Record.Request.Domain != "" {
		fmt.Printf("    domain       %s\n", p.Record.Request.Domain)
	}
	fmt.Printf("    from         %s\n", p.Record.SourceAddr)
	fmt.Printf("    key          %s\n", short(p.Record.Fingerprint, 16))
	if p.Record.Identity != "" {
		fmt.Printf("    identity     %s (binder %s)\n", short(p.Record.Identity, 16), p.Record.Binder)
	}
	fmt.Printf("    asked        %s\n", p.Record.ReceivedAt.Local().Format("2006-01-02 15:04:05"))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range hintOrder(p.Record.Request.Hints) {
		fmt.Fprintf(w, "    %s\t%s\n", k, p.Record.Request.Hints[k])
	}
	w.Flush()
}

// hintOrder reads the way somebody recognizing a deployment reads: what it
// runs on, then what it is, then the name it happens to have. Anything a
// future connector adds follows, in whatever order it sorts.
func hintOrder(hints map[string]string) []string {
	known := []string{"platform", "project", "environment", "service", "region", "hostname"}

	out := make([]string, 0, len(hints))
	seen := map[string]bool{}
	for _, k := range known {
		if hints[k] != "" {
			out = append(out, k)
			seen[k] = true
		}
	}

	var rest []string
	for k := range hints {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)

	return append(out, rest...)
}

// short truncates an identifier for display without assuming its length.
func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func prefixes(list []netip.Prefix) string {
	if len(list) == 0 {
		return "-"
	}

	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.String())
	}
	return strings.Join(out, ",")
}
