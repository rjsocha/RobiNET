package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rjsocha/robinet/internal/wrak"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

// File is the hub's configuration on disk.
//
// A file rather than flags, because a binder is a name plus a list of ssh keys
// and that does not belong on a command line.
type File struct {
	Public struct {
		// Endpoint is the host connectors dial, without a port. The port is
		// per instance.
		Endpoint string `yaml:"endpoint"`

		// Bind is the address nebula listens on for every instance.
		Bind string `yaml:"bind"`
	} `yaml:"public"`

	API struct {
		Listen string `yaml:"listen"`

		// Entrypoint is http or https. http is for a hub behind something that
		// terminates TLS already.
		Entrypoint string `yaml:"entrypoint"`

		TLS struct {
			Cert string `yaml:"cert"`
			Key  string `yaml:"key"`
		} `yaml:"tls"`
	} `yaml:"api"`

	State struct {
		Path string `yaml:"path"`
	} `yaml:"state"`

	// Overlays is the address space, one entry per family, each written as
	// superprefix plus the size handed to each instance: 198.19.0.0/16/24 is a
	// /16 carved into /24s.
	//
	// The family is read off the prefix rather than named, because a prefix
	// already says which one it is and a hub that had to be told would be a
	// hub that could be told wrong.
	Overlays []string `yaml:"overlays"`

	// Ports is the udp range instances are allocated from.
	Ports string `yaml:"ports"`

	// MTU of this host's link, handed to connectors so they can take the lower
	// of that and their own.
	MTU uint32 `yaml:"mtu"`

	// Relay lets a lighthouse carry traffic for members that cannot punch
	// through. Without it, a member behind symmetric NAT has no way in.
	Relay *bool `yaml:"relay"`

	// DNS makes each lighthouse answer for the members of its instance, by
	// their certificate names, on its own overlay address. On unless said
	// otherwise: the lighthouse is the one party that sees every member, so it
	// already holds the answer.
	//
	// Turning it off costs the names and nothing else. The device stays either
	// way, because a lighthouse without one answers nothing at all, not even
	// ping.
	DNS *bool `yaml:"dns"`

	Security struct {
		// Token is known to every operator who may create an instance here. It
		// goes into the signed bootstrap message and never travels.
		Token string `yaml:"token"`
	} `yaml:"security"`

	Binder []struct {
		Name string   `yaml:"name"`
		Key  []string `yaml:"key"`
	} `yaml:"binder"`

	// Warnings are things worth saying out loud that are not reasons to
	// refuse, such as a configuration directory that is not there yet.
	Warnings []string `yaml:"-"`
}

// LoadFile reads and validates the hub configuration.
//
// Extra directories are scanned for *.yaml and *.yml, in the order given and
// alphabetically within each, and merged on top. Binders accumulate, so a
// directory of one file per operator is a natural way to manage them; anything
// else set later wins.
func LoadFile(path string, dirs ...string) (*File, error) {
	f, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		files, err := configFilesIn(dir)
		if errors.Is(err, os.ErrNotExist) {
			// A directory that does not exist yet is a normal state on a fresh
			// host, and refusing to start over it would be theatre.
			f.Warnings = append(f.Warnings, fmt.Sprintf("%s does not exist, no binder fragments read from it", dir))
			continue
		}
		if err != nil {
			return nil, err
		}

		for _, extra := range files {
			part, err := readConfig(extra)
			if err != nil {
				return nil, err
			}
			f.merge(part)
		}
	}

	f.applyDefaults()
	return f, f.validate()
}

func readConfig(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}

	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", path, err)
	}

	return &f, nil
}

// configFilesIn lists the yaml files of a directory, sorted, so the result
// does not depend on the order the filesystem hands them back.
func configFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", dir, err)
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
	return out, nil
}

// merge folds another file into this one. A value that was not set stays as it
// was, so a fragment can say one thing without restating everything.
func (f *File) merge(other *File) {
	if other.Public.Endpoint != "" {
		f.Public.Endpoint = other.Public.Endpoint
	}
	if other.Public.Bind != "" {
		f.Public.Bind = other.Public.Bind
	}
	if other.API.Listen != "" {
		f.API.Listen = other.API.Listen
	}
	if other.API.TLS.Cert != "" {
		f.API.TLS.Cert = other.API.TLS.Cert
	}
	if other.API.TLS.Key != "" {
		f.API.TLS.Key = other.API.TLS.Key
	}
	if other.API.Entrypoint != "" {
		f.API.Entrypoint = other.API.Entrypoint
	}
	if other.State.Path != "" {
		f.State.Path = other.State.Path
	}
	if len(other.Overlays) > 0 {
		f.Overlays = other.Overlays
	}
	if other.Ports != "" {
		f.Ports = other.Ports
	}
	if other.MTU != 0 {
		f.MTU = other.MTU
	}
	if other.Relay != nil {
		f.Relay = other.Relay
	}
	if other.DNS != nil {
		f.DNS = other.DNS
	}
	if other.Security.Token != "" {
		f.Security.Token = other.Security.Token
	}

	// Binders are the reason this exists: they add up rather than replace.
	f.Binder = append(f.Binder, other.Binder...)
	f.Warnings = append(f.Warnings, other.Warnings...)
}

func (f *File) applyDefaults() {
	if f.Public.Bind == "" {
		f.Public.Bind = "0.0.0.0"
	}
	if f.API.Listen == "" {
		f.API.Listen = ":8443"
	}
	if f.State.Path == "" {
		f.State.Path = "/var/lib/robinet/hub.json"
	}
	if len(f.Overlays) == 0 {
		f.Overlays = []string{"198.19.0.0/16/24"}
	}
	if f.API.Entrypoint == "" {
		f.API.Entrypoint = EntrypointHTTPS
	}
	if f.Ports == "" {
		f.Ports = "20000-24999"
	}
	if f.MTU == 0 {
		f.MTU = 1500
	}
	if f.Relay == nil {
		on := true
		f.Relay = &on
	}
	if f.DNS == nil {
		on := true
		f.DNS = &on
	}
}

// refuseOverlap reports pools that cover each other. Allocation walks each
// pool separately and knows nothing about the others, so an overlap would hand
// the same prefix out twice.
func refuseOverlap(pools []Pool) error {
	for i, a := range pools {
		for _, b := range pools[i+1:] {
			if a.Prefix.Overlaps(b.Prefix) {
				return fmt.Errorf("overlays %s and %s overlap", a.Prefix, b.Prefix)
			}
		}
	}
	return nil
}

// How the API is served. https is the default, and http is for a hub behind
// something that terminates TLS already.
const (
	EntrypointHTTP  = "http"
	EntrypointHTTPS = "https"
)

// ErrNoBinders says the configuration is otherwise fine but nobody is allowed
// to create an instance yet. It is separate because that is the one thing an
// operator has to decide, and a caller may want to get everything else ready
// while waiting for it.
var ErrNoBinders = errors.New("at least one binder is required, nobody could create an instance otherwise")

func (f *File) validate() error {
	if err := validateEndpoint(f.Public.Endpoint); err != nil {
		return err
	}
	if strings.TrimSpace(f.Security.Token) == "" {
		return fmt.Errorf("security.token is required, it is what a bootstrap signature proves knowledge of")
	}
	if len(f.Binder) == 0 {
		return ErrNoBinders
	}
	return nil
}

// validateEndpoint keeps a url out of a field that is a bare host.
//
// The endpoint is what a connector dials over UDP, composed with the
// instance's own port, and it is also the name on the hub's own certificate.
// It is not the API url: that one the tenant passes with --hub.
func validateEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)

	if endpoint == "" {
		return fmt.Errorf("public.endpoint is required, connectors need a host to dial")
	}

	bare := bareHost(endpoint)
	if bare == endpoint {
		return nil
	}

	switch {
	case strings.Contains(endpoint, "://"):
		return fmt.Errorf("public.endpoint is a bare host, not a url, and each instance brings its own port: write %s", bare)
	case strings.Contains(endpoint, "/"):
		return fmt.Errorf("public.endpoint is a bare host: drop the path, write %s", bare)
	default:
		return fmt.Errorf("public.endpoint carries no port, each instance has its own: write %s", bare)
	}
}

// bareHost reduces whatever was written to the host alone.
func bareHost(s string) string {
	if _, rest, found := strings.Cut(s, "://"); found {
		s = rest
	}
	if before, _, found := strings.Cut(s, "/"); found {
		s = before
	}

	// An IPv6 literal is full of colons, so only strip a port when what is
	// left of the last one is not itself an address.
	if strings.HasPrefix(s, "[") {
		if host, _, err := net.SplitHostPort(s); err == nil {
			return host
		}
		return strings.Trim(s, "[]")
	}

	if _, err := netip.ParseAddr(s); err == nil {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}

	return s
}

// Config turns the file into what the hub runs on.
func (f *File) Config(log *slog.Logger) (Config, error) {
	var pools, pools6 []Pool

	for _, raw := range f.Overlays {
		prefix, size, err := ParsePool(raw)
		if err != nil {
			return Config{}, err
		}

		// Which family it is is a property of the prefix. A hub that had to be
		// told could be told wrong.
		pool := Pool{Prefix: prefix, Size: size}
		if prefix.Addr().Is4() {
			pools = append(pools, pool)
		} else {
			pools6 = append(pools6, pool)
		}
	}

	// Two pools covering the same addresses would hand the same prefix out
	// twice, each unaware of the other.
	if err := refuseOverlap(append(append([]Pool{}, pools...), pools6...)); err != nil {
		return Config{}, err
	}

	if len(pools) == 0 {
		return Config{}, fmt.Errorf("overlays has no IPv4 pool, and every member gets an IPv4 address")
	}

	if f.API.Entrypoint != EntrypointHTTP && f.API.Entrypoint != EntrypointHTTPS {
		return Config{}, fmt.Errorf("api.entrypoint is %q, wanted http or https", f.API.Entrypoint)
	}

	min, max, err := parsePortRange(f.Ports)
	if err != nil {
		return Config{}, err
	}

	binders := Binders{}
	for _, b := range f.Binder {
		name := strings.TrimSpace(b.Name)
		if name == "" {
			return Config{}, fmt.Errorf("a binder has no name")
		}
		if _, duplicate := binders[name]; duplicate {
			return Config{}, fmt.Errorf("binder %s is declared twice", name)
		}

		keys, err := wrak.ParseAuthorizedKeys(b.Key)
		if err != nil {
			return Config{}, fmt.Errorf("binder %s: %w", name, err)
		}
		if len(keys) == 0 {
			return Config{}, fmt.Errorf("binder %s has no keys, so nothing could authenticate as it", name)
		}

		binders[name] = &Binder{Keys: keys}
	}

	// The same key under two binders would make a signature ambiguous, and
	// guessing which one was meant is not something to do quietly.
	seen := map[string]string{}
	for name, b := range binders {
		for _, key := range b.Keys {
			fingerprint := ssh.FingerprintSHA256(key)
			if other, duplicate := seen[fingerprint]; duplicate {
				return Config{}, fmt.Errorf("binders %s and %s share a key (%s)", other, name, fingerprint)
			}
			seen[fingerprint] = name
		}
	}

	return Config{
		APIAddr:        f.API.Listen,
		NebulaBind:     f.Public.Bind,
		PublicEndpoint: f.Public.Endpoint,
		PortMin:        min,
		PortMax:        max,
		Overlays:       pools,
		Overlays6:      pools6,
		Token:          f.Security.Token,
		Binders:        binders,
		StatePath:      f.State.Path,
		MTU:            f.MTU,
		Relay:          *f.Relay,
		DNS:            *f.DNS,
		Logger:         log,
	}, nil
}

// Binder is who may create instances here: a name and the ssh keys that speak
// for it. The token is shared by the whole hub, so a binder is only a list of
// keys and a label for the log.
type Binder struct {
	Keys []ssh.PublicKey
}

// Binders is the whole set, keyed by name.
type Binders map[string]*Binder

// Authorized returns the keys that may bootstrap as this binder.
func (b *Binder) Authorized() []ssh.PublicKey { return b.Keys }

// Keys returns every authorized key across every binder, which is what a
// bootstrap signature is checked against: a caller does not have to say which
// binder they are, the key already says it.
func (bs Binders) AllKeys() []ssh.PublicKey {
	var out []ssh.PublicKey
	for _, b := range bs {
		out = append(out, b.Keys...)
	}
	return out
}

// Match names the binder a key speaks for.
func (bs Binders) Match(key ssh.PublicKey) (string, bool) {
	for name, b := range bs {
		for _, candidate := range b.Keys {
			if wrak.SameKey(key, candidate) {
				return name, true
			}
		}
	}
	return "", false
}

// parsePortRange reads low-high.
func parsePortRange(s string) (uint16, uint16, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("port range %q is not low-high", s)
	}

	min, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("bad low port: %w", err)
	}
	max, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("bad high port: %w", err)
	}
	if min > max {
		return 0, 0, fmt.Errorf("port range %q is inverted", s)
	}

	return uint16(min), uint16(max), nil
}
