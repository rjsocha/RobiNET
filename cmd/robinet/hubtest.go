package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rjsocha/robinet/internal/hub"
	"golang.org/x/crypto/ssh"
)

// testHubConfig reports what a configuration resolves to, without starting
// anything.
//
// It prints the effective values rather than only saying "ok", because most
// configuration mistakes are valid syntax that means something other than what
// was intended.
func testHubConfig(configPath string, configDirs []string) error {
	fmt.Printf("config     %s\n", configPath)
	for _, dir := range configDirs {
		files, missing := yamlFilesIn(dir)
		if missing {
			fmt.Printf("           ! %s does not exist\n", dir)
			continue
		}
		if len(files) == 0 {
			fmt.Printf("           ! %s holds no yaml\n", dir)
			continue
		}
		for _, f := range files {
			fmt.Printf("           + %s\n", f)
		}
	}

	file, err := hub.LoadFile(configPath, configDirs...)
	incomplete := errors.Is(err, hub.ErrNoBinders)
	if err != nil && !incomplete {
		fmt.Println()
		return err
	}

	cfg, cfgErr := file.Config(nil)
	if cfgErr != nil && !incomplete {
		fmt.Println()
		return cfgErr
	}

	fmt.Printf("endpoint   %s\n", file.Public.Endpoint)
	fmt.Printf("api        %s (%s)\n", file.API.Listen, tlsMode(file))
	if p := existingPin(file); p != "" {
		// What a client verifies this hub by, when no authority vouches for it.
		fmt.Printf("           pin %s\n", p)
	}
	fmt.Printf("state      %s\n", file.State.Path)

	if cfgErr == nil {
		instances := 0
		label := "overlays"
		for _, p := range cfg.Overlays {
			room := countSubnets(p.Prefix.Bits(), p.Size)
			instances += room
			fmt.Printf("%-10s %s in /%d, room for %d instances\n", label, p.Prefix, p.Size, room)
			label = ""
		}
		for _, p := range cfg.Overlays6 {
			fmt.Printf("%-10s %s in /%d\n", label, p.Prefix, p.Size)
			label = ""
		}
		if len(cfg.Overlays6) == 0 {
			// Worth saying plainly: without one no member of any instance here
			// can carry an IPv6 route, whatever it announces.
			fmt.Printf("%-10s no ipv6 pool, so no instance here can carry an ipv6 route\n", label)
		}

		ports := int(cfg.PortMax) - int(cfg.PortMin) + 1
		fmt.Printf("ports      %s, room for %d instances\n", file.Ports, ports)

		// Whichever runs out first is the real limit, and it is worth saying
		// so before somebody wonders why the 5001st instance was refused.
		if limit := min(instances, ports); limit < max(instances, ports) {
			fmt.Printf("           the smaller of the two applies: %d instances\n", limit)
		}
	}

	fmt.Printf("relay      %s\n", enabled(file.Relay != nil && *file.Relay))
	fmt.Printf("mtu        %d\n", file.MTU)

	if incomplete {
		fmt.Println("binders    none")
		fmt.Println()
		return hub.ErrNoBinders
	}

	fmt.Println("binders")
	names := make([]string, 0, len(cfg.Binders))
	for name := range cfg.Binders {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for i, key := range cfg.Binders[name].Authorized() {
			label := name
			if i > 0 {
				label = ""
			}
			fmt.Printf("  %-10s %s %s\n", label, ssh.FingerprintSHA256(key), keyComment(key))
		}
	}

	fmt.Println()
	fmt.Println("ok")
	return nil
}

func tlsMode(file *hub.File) string {
	switch {
	case file.API.Entrypoint == hub.EntrypointHTTP:
		return "plain http, something else terminates TLS"
	case file.API.TLS.Cert != "" && file.API.TLS.Key != "":
		return "certificate from " + file.API.TLS.Cert
	default:
		return "self signed certificate, clients need --insecure"
	}
}

func enabled(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

// countSubnets is how many prefixes of size fit in a pool of bits.
func countSubnets(bits, size int) int {
	shift := size - bits
	if shift < 0 {
		return 0
	}
	if shift > 30 {
		return 1 << 30
	}
	return 1 << shift
}

func keyComment(key ssh.PublicKey) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func yamlFilesIn(dir string) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, true
	}

	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".yaml", ".yml":
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}

	sort.Strings(out)
	return out, false
}

// existingPin reports the pin of the certificate this hub already generated,
// or nothing when it has not started yet.
func existingPin(file *hub.File) string {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(filepath.Dir(file.State.Path), "api-cert.pem"),
		filepath.Join(filepath.Dir(file.State.Path), "api-key.pem"),
	)
	if err != nil {
		return ""
	}
	return certPin(cert)
}
