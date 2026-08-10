package netstack

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

const defaultResolvConf = "/etc/resolv.conf"

// dnsUpstream is the resolver that queries sent to our own overlay address are
// forwarded to. Only the first entry is used.
func (s *Service) dnsUpstream() string {
	if len(s.opts.DNSUpstreams) == 0 {
		return ""
	}
	return s.opts.DNSUpstreams[0]
}

// resolveDNSUpstreams fills in the upstream list from the host resolver
// configuration when the caller did not provide one.
func resolveDNSUpstreams(opts *Options) error {
	if len(opts.DNSUpstreams) > 0 {
		normalized := make([]string, 0, len(opts.DNSUpstreams))
		for _, u := range opts.DNSUpstreams {
			addr, err := normalizeResolver(u)
			if err != nil {
				return fmt.Errorf("invalid DNS upstream %q: %w", u, err)
			}
			normalized = append(normalized, addr)
		}
		opts.DNSUpstreams = normalized
		return nil
	}

	path := opts.DNSResolvConf
	if path == "" {
		path = defaultResolvConf
	}

	upstreams, err := nameserversFromResolvConf(path)
	if err != nil {
		return err
	}
	if len(upstreams) == 0 {
		return fmt.Errorf("no nameserver found in %s, set an upstream explicitly", path)
	}

	opts.DNSUpstreams = upstreams
	return nil
}

// nameserversFromResolvConf reads nameserver entries and returns them as
// dialable addresses.
func nameserversFromResolvConf(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the resolver config: %w", err)
	}
	defer f.Close()

	var upstreams []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// resolv.conf accepts both comment markers
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}

		addr, err := normalizeResolver(fields[1])
		if err != nil {
			// host state we do not control, skip what we cannot use
			continue
		}
		upstreams = append(upstreams, addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read the resolver config: %w", err)
	}

	return upstreams, nil
}

// normalizeResolver turns a bare address or a host:port into a dialable address.
func normalizeResolver(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty address")
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(addr.Unmap().String(), "53"), nil
	}

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", fmt.Errorf("not an ip address: %s", host)
	}
	if port == "" {
		return "", errors.New("missing port")
	}

	return net.JoinHostPort(host, port), nil
}
