package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/pin"
	"github.com/spf13/cobra"
)

// newHubCmd groups everything the hub does. It does nothing by itself: a
// command that started a service when run with no arguments is a command
// somebody starts by accident.
func newHubCmd() *cobra.Command {
	var (
		configPath string
		configDirs []string
	)

	cmd := &cobra.Command{
		Use:   "hub",
		Short: "The hub: a lighthouse per instance and the enrollment mailbox",
		Long: `The hub is the only part that needs a public address. It runs one nebula
lighthouse per instance, allocates address space and ports, and carries
enrollment requests between connectors and the people who decide about them.

It holds no certificate authority key, so it can never produce an identity, and
the lighthouses run with the tun device disabled, so it needs neither
NET_ADMIN nor /dev/net/tun.

Configuration is a file, because a binder is a name and a list of ssh keys and
that does not belong on a command line. See doc/hub.yaml for an example.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		newHubRunCmd(&configPath, &configDirs),
		newHubInitCmd(&configPath),
		newHubInstallCmd(&configPath, &configDirs),
		newHubTestCmd(&configPath, &configDirs),
		newHubCleanupCmd(&configPath),
		newHubListCmd(&configPath, &configDirs),
		newHubShowCmd(&configPath, &configDirs),
		newHubMachinesCmd(&configPath, &configDirs),
		newHubMembersCmd(&configPath, &configDirs),
	)

	// On the parent, so every subcommand takes them the same way.
	f := cmd.PersistentFlags()
	f.StringVarP(&configPath, "config", "c", "/etc/site/robinet/hub.yaml", "configuration file")
	f.StringArrayVar(&configDirs, "config-dir", []string{"/etc/site/robinet/binder"},
		"directory of extra *.yaml fragments, merged on top, repeatable")

	return cmd
}

// newHubRunCmd is the service. It runs in the foreground and is what the unit
// starts.
func newHubRunCmd(configPath *string, configDirs *[]string) *cobra.Command {
	var logLevel string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the hub in the foreground",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			configPath, configDirs := *configPath, *configDirs

			log := newLogger(logLevel)

			file, err := hub.LoadFile(configPath, configDirs...)
			if err != nil {
				return err
			}

			cfg, err := file.Config(log)
			if err != nil {
				return err
			}

			h, err := hub.New(cfg)
			if err != nil {
				return err
			}
			defer h.Close()

			srv := &http.Server{
				Addr:              cfg.APIAddr,
				Handler:           h.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}

			go func() {
				<-ctx.Done()
				srv.Close()
			}()

			for _, warning := range file.Warnings {
				log.Warn(warning)
			}

			log.Info("hub listening",
				"api", cfg.APIAddr,
				"endpoint", cfg.PublicEndpoint,
				"overlays", strings.Join(file.Overlays, " "),
				"ports", file.Ports,
				"relay", cfg.Relay,
				"binders", len(cfg.Binders),
			)

			switch {
			case file.API.Entrypoint == hub.EntrypointHTTP:
				err = srv.ListenAndServe()
			case file.API.TLS.Cert != "" && file.API.TLS.Key != "":
				err = srv.ListenAndServeTLS(file.API.TLS.Cert, file.API.TLS.Key)
			default:
				// A self signed certificate is enough here: a bootstrap proves
				// knowledge of a token that never travels, every later request
				// is signed, and a certificate the hub carries cannot be forged
				// by whoever carries it.
				cert, gerr := selfSignedCert(cfg.PublicEndpoint, filepath.Dir(cfg.StatePath))
				if gerr != nil {
					return gerr
				}
				srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

				// The pin is how somebody verifies this hub without an
				// authority vouching for it, so it is printed where they will
				// look rather than left to be computed.
				log.Info("serving with a self signed certificate",
					"pin", certPin(cert),
					"clients", "--insecure, or --pin with the value above")
				err = srv.ListenAndServeTLS("", "")
			}

			if err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&logLevel, "log", "info", "log level")

	return cmd
}

// newHubInitCmd writes a starter configuration, and nothing else: what a hub
// hands out is a decision, and a file is where decisions are written down.
func newHubInitCmd(configPath *string) *cobra.Command {
	var endpoint string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return elevate()
			}
			return writeHubConfig(*configPath, endpoint)
		},
	}

	cmd.Flags().StringVar(&endpoint, "endpoint", "", "the address connectors will dial")

	return cmd
}

func newHubInstallCmd(configPath *string, configDirs *[]string) *cobra.Command {
	var enable bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install and start this hub as a systemd service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return elevate()
			}
			return installHub(cmd.Context(), *configPath, *configDirs, enable)
		},
	}

	cmd.Flags().BoolVar(&enable, "enable", true, "enable and start it, rather than only writing the unit")

	return cmd
}

func newHubTestCmd(configPath *string, configDirs *[]string) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Check the configuration and print what it resolves to",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return testHubConfig(*configPath, *configDirs)
		},
	}
}

func newHubCleanupCmd(configPath *string) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Remove the service, the state and the configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return elevate()
			}
			return cleanupHub(cmd.Context(), *configPath, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "required: this cannot be undone")

	return cmd
}

// selfSignedCert loads the hub's own certificate, generating it once.
//
// Once, and kept: a certificate regenerated at every start would have a new
// public key at every start, and a client that pinned the hub's key would be
// refused every time the service was restarted. Keeping it is what makes a pin
// a usable answer to a hub no authority vouches for.
func selfSignedCert(host, dir string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, "api-cert.pem")
	keyPath := filepath.Join(dir, "api-key.pem")

	if existing, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return existing, nil
	}

	cert, err := generateSelfSigned(host)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func generateSelfSigned(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// certPin renders the hash a client pins this certificate by.
func certPin(cert tls.Certificate) string {
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	return pin.Of(parsed)
}
