package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/rjsocha/robinet/internal/connector"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var (
		hubURL     string
		instance   string
		token      string
		name       string
		routes     []string
		domains    []string
		noDiscover bool
		stateDir   string
		mtu        uint32
		insecure   bool
		dns        bool
		logLevel   string
	)

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Enroll and stay connected from inside the network being exposed",
		Long: `connect runs where there is no tun device and no NET_ADMIN. It generates an
identity on first start, announces the networks this host is attached to, and
waits to be admitted. Once approved it forwards TCP and UDP from the mesh into
the network it lives on, and answers DNS with the resolver it sees.

Every flag can be given as an environment variable instead, so a platform that
offers nothing else is enough. The state directory has to survive restarts,
otherwise this connector comes back as a new identity each time.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Before parsing, because a template ships with this and whoever
			// deployed it may not have read far enough to replace it.
			if isPlaceholder(hubURL) {
				return refusePlaceholder(cmd.Context())
			}

			base, id, shorthandToken, err := parseEndpoint(hubURL)
			if err != nil {
				return err
			}
			hubURL = base
			if id != "" {
				instance = id
			}
			if shorthandToken != "" && token == "" {
				token = shorthandToken
			}

			if hubURL == "" || instance == "" {
				return fmt.Errorf("--endpoint is required, as host/instance[/token] or a full enrollment url")
			}

			var announced []netip.Prefix
			for _, raw := range routes {
				raw = strings.TrimSpace(raw)
				if raw == "" {
					continue
				}
				p, err := netip.ParsePrefix(raw)
				if err != nil {
					return fmt.Errorf("bad prefix %q: %w", raw, err)
				}
				announced = append(announced, p)
			}

			return connector.Run(cmd.Context(), connector.Config{
				HubURL:              hubURL,
				Instance:            instance,
				SharedToken:         token,
				Name:                name,
				Routes:              announced,
				Domains:             domains,
				DisableAutodiscover: noDiscover,
				StateDir:            stateDir,
				MTU:                 mtu,
				Insecure:            insecure,
				DNS:                 dns,
				Logger:              newLogger(logLevel),
			})
		},
	}

	f := cmd.Flags()
	f.StringVar(&hubURL, "endpoint", envOr("ROBINET_ENDPOINT", ""),
		"host/instance[/token], or a full enrollment url [ROBINET_ENDPOINT]")
	f.StringVar(&instance, "instance", envOr("ROBINET_INSTANCE", ""), "instance id on the hub [ROBINET_INSTANCE]")
	f.StringVar(&token, "token", envOr("ROBINET_TOKEN", ""), "shared token to sign the enrollment with [ROBINET_TOKEN]")
	f.StringVar(&name, "name", envOr("ROBINET_NAME", ""), "label shown to whoever approves this [ROBINET_NAME]")
	f.StringSliceVar(&routes, "announce-routes", envList("ROBINET_ANNOUNCE_ROUTES"), "prefixes to announce [ROBINET_ANNOUNCE_ROUTES]")
	f.StringSliceVar(&domains, "domains", envList("ROBINET_DOMAINS"), "domains this connector can resolve [ROBINET_DOMAINS]")
	f.BoolVar(&noDiscover, "disable-autodiscover", envBool("ROBINET_DISABLE_AUTODISCOVER", false), "do not detect attached networks [ROBINET_DISABLE_AUTODISCOVER]")
	f.StringVar(&stateDir, "state", envOr("ROBINET_STATE", "/var/lib/robinet"), "state directory, must survive restarts [ROBINET_STATE]")
	f.Uint32Var(&mtu, "mtu", uint32(envUint("ROBINET_MTU", 0)), "override the stack mtu [ROBINET_MTU]")
	f.BoolVar(&insecure, "insecure", envBool("ROBINET_INSECURE", true), "skip verification of the hub's TLS certificate [ROBINET_INSECURE]")
	f.BoolVar(&dns, "dns", envBool("ROBINET_DNS", true), "forward DNS to the resolver this host uses [ROBINET_DNS]")
	f.StringVar(&logLevel, "log", envOr("ROBINET_LOG", "info"), "log level [ROBINET_LOG]")

	return cmd
}

// DefaultAPIPort is what the shorthand assumes, matching the hub's own default.
const DefaultAPIPort = "8443"

// parseEndpoint reads either form of what a connector is told.
//
//	192.0.2.10/76615289c33b3186            shorthand
//	192.0.2.10/76615289c33b3186/sekret     shorthand carrying the token
//	192.0.2.10:9443/76615289c33b3186       shorthand on another port
//	https://hub.example.com:8443/v1/enroll/76615289c33b3186
//
// The shorthand exists because this is usually typed into a platform's
// environment by hand, and one field is easier to get right than three. A full
// url is taken as it is, and then the token has to be given separately, since
// a url has nowhere sensible to put it.
func parseEndpoint(raw string) (base, instance, token string, _ error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", nil
	}

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		const marker = "/v1/enroll/"

		i := strings.Index(raw, marker)
		if i < 0 {
			// A bare hub url: the instance comes from its own flag.
			return strings.TrimRight(raw, "/"), "", "", nil
		}

		instance = strings.Trim(raw[i+len(marker):], "/")
		if instance == "" {
			return "", "", "", fmt.Errorf("enrollment url %q names no instance", raw)
		}
		return raw[:i], instance, "", nil
	}

	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("endpoint %q is not host/instance[/token] and not a url", raw)
	}
	if len(parts) > 3 {
		return "", "", "", fmt.Errorf("endpoint %q has more parts than host/instance[/token]", raw)
	}

	host := parts[0]
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), DefaultAPIPort)
	}

	if len(parts) == 3 {
		token = parts[2]
	}

	return "https://" + host, parts[1], token, nil
}

func envList(name string) []string {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

func envUint(name string, fallback uint64) uint64 {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}

	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return fallback
	}
	return n
}
