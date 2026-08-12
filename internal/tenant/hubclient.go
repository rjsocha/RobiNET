package tenant

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/hub"
	"github.com/rjsocha/robinet/internal/pin"
	"github.com/rjsocha/robinet/internal/wrak"
	"golang.org/x/crypto/ssh"
)

// hubClient talks to the hub. Every call after registration is signed with
// this machine's identity, so there is no bearer token to leak.
type hubClient struct {
	base     string
	identity *wrak.Identity
	client   *http.Client
}

func newHubClient(base, identity string, insecure bool, hubPin string) (*hubClient, error) {
	id, err := wrak.ParseIdentity(identity)
	if err != nil {
		return nil, err
	}

	client, err := httpClient(insecure, hubPin)
	if err != nil {
		return nil, err
	}

	return &hubClient{
		base:     strings.TrimRight(base, "/"),
		identity: id,
		client:   client,
	}, nil
}

// httpClient verifies the hub by a pin when there is one, by the usual chain
// when there is not, and by nothing when told to.
func httpClient(insecure bool, hubPin string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	switch {
	case hubPin != "":
		cfg, err := pin.TLSConfig(hubPin)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = cfg
	case insecure:
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

// register introduces this machine to a hub, signing with an ssh key.
//
// Every key the agent holds is tried in turn: which of them a hub knows is the
// hub's business, not something an operator should have to remember.
func register(ctx context.Context, opts JoinOptions, identity *wrak.Identity) (*hub.RegisterResponse, error) {
	base := strings.TrimRight(opts.HubURL, "/")
	endpoint := base + "/v1/register"

	host, err := hostOf(endpoint)
	if err != nil {
		return nil, err
	}

	bootstrap := wrak.Bootstrap{
		API:      host,
		Token:    opts.Token,
		Name:     opts.Name,
		Identity: identity.Public(),
	}

	signers, err := bootstrapSigners(opts)
	if err != nil {
		return nil, err
	}

	client, err := httpClient(opts.Insecure, opts.Pin)
	if err != nil {
		return nil, err
	}

	var tried []string
	for i, signer := range signers {
		signature, err := bootstrap.Sign(signer)
		if err != nil {
			return nil, err
		}

		body, err := json.Marshal(hub.RegisterRequest{
			Name:      opts.Name,
			Identity:  identity.Public(),
			Signature: string(signature),
		})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			tried = append(tried, ssh.FingerprintSHA256(signer.PublicKey()))
			if i < len(signers)-1 {
				continue
			}
			// The hub answers the same way for a wrong token and an unknown
			// key, so this cannot say which it was.
			return nil, fmt.Errorf("registration rejected: either the token is wrong or none of these keys is known to the hub: %s",
				strings.Join(tried, ", "))
		}

		if resp.StatusCode >= 300 {
			err := responseError(resp)
			resp.Body.Close()
			return nil, err
		}

		var out hub.RegisterResponse
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		out.SignedBy = ssh.FingerprintSHA256(signer.PublicKey())
		return &out, nil
	}

	return nil, fmt.Errorf("no ssh key to sign the registration with")
}

// createInstance asks for a new instance, owned by this machine.
func (c *hubClient) createInstance(ctx context.Context, name, sharedToken string) (*hub.CreateInstanceResponse, error) {
	var out hub.CreateInstanceResponse
	err := c.do(ctx, http.MethodPost, "/v1/instances",
		hub.CreateInstanceRequest{Name: name, SharedToken: sharedToken}, &out)
	return &out, err
}

// instances lists what this machine can see.
func (c *hubClient) instances(ctx context.Context) ([]hub.InstanceSummary, error) {
	var out []hub.InstanceSummary
	err := c.do(ctx, http.MethodGet, "/v1/instances", nil, &out)
	return out, err
}

// activate uploads the certificates only the owner can produce, which starts
// the lighthouse.
func (c *hubClient) activate(ctx context.Context, instance, caPEM, certPEM string) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/lighthouse",
		hub.LighthouseRequest{CA: caPEM, Certificate: certPEM}, nil)
}

// pending pulls the requests waiting for a decision on an instance we own.
func (c *hubClient) pending(ctx context.Context, instance string) ([]*hub.Record, error) {
	var out []*hub.Record
	err := c.do(ctx, http.MethodGet, "/v1/instances/"+instance+"/requests", nil, &out)
	return out, err
}

// decide posts what the owner decided.
func (c *hubClient) decide(ctx context.Context, instance, requestID string, d enroll.Decision) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/requests/"+requestID, d, nil)
}

// forget drops a record on the hub.
func (c *hubClient) forget(ctx context.Context, instance, requestID string) error {
	return c.do(ctx, http.MethodDelete, "/v1/instances/"+instance+"/requests/"+requestID, nil, nil)
}

// ban blocklists a member of an instance we own.
func (c *hubClient) ban(ctx context.Context, instance, member, note string) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/ban",
		hub.BanRequest{Member: member, Note: note}, nil)
}

// unban lets one back in.
func (c *hubClient) unban(ctx context.Context, instance, member, note string) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/unban",
		hub.BanRequest{Member: member, Note: note}, nil)
}

// setToken replaces the secret new enrollments are authenticated with.
func (c *hubClient) setToken(ctx context.Context, instance, token string) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/token",
		hub.TokenRequest{SharedToken: token}, nil)
}

// join asks to be let into an instance somebody else owns.
func (c *hubClient) join(ctx context.Context, instance, name, publicKey string) error {
	return c.do(ctx, http.MethodPost, "/v1/instances/"+instance+"/join",
		hub.JoinRequest{Name: name, PublicKey: publicKey}, nil)
}

// joinResult asks what happened to our own request.
func (c *hubClient) joinResult(ctx context.Context, instance string) (*enroll.Result, error) {
	var out enroll.Result
	err := c.do(ctx, http.MethodGet, "/v1/instances/"+instance+"/join", nil, &out)
	return &out, err
}

// deleteInstance asks the hub to forget an instance. Only its owner may.
func (c *hubClient) deleteInstance(ctx context.Context, instance string) error {
	return c.do(ctx, http.MethodDelete, "/v1/instances/"+instance, nil, nil)
}

// removeMember forgets one, which only an owner may.
func (c *hubClient) removeMember(ctx context.Context, instance, member string) (*hub.Member, error) {
	var out hub.Member
	err := c.do(ctx, http.MethodDelete, "/v1/instances/"+instance+"/members/"+member, nil, &out)
	return &out, err
}

// members lists who is inside an instance.
func (c *hubClient) members(ctx context.Context, instance string) ([]*hub.Member, error) {
	var out []*hub.Member
	err := c.do(ctx, http.MethodGet, "/v1/instances/"+instance+"/members", nil, &out)
	return out, err
}

// routes reads the table every member shares.
func (c *hubClient) routes(ctx context.Context, instance string) (*hub.RouteTable, error) {
	var out hub.RouteTable
	err := c.do(ctx, http.MethodGet, "/v1/instances/"+instance+"/routes", nil, &out)
	return &out, err
}

func (c *hubClient) do(ctx context.Context, method, path string, in, out any) error {
	var raw []byte
	if in != nil {
		var err error
		raw, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	var body io.Reader
	if raw != nil {
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.identity.SignRequest(req, raw); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return responseError(resp)
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// responseError says why the hub refused, in the hub's own words.
//
// The refusal reaches a terminal by way of the daemon, so what it says is what
// the operator reads. The status line and the machine-readable code carry
// nothing they do not already know - the message names the thing and usually
// the way out of it - and prefixing every refusal with "hub returned 400 Bad
// Request: bad_request:" only buries that. They stand in when there is no
// message to print, which is the one case where they are all there is.
func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	var e enroll.Error
	if json.Unmarshal(body, &e) == nil && e.Code != "" {
		if e.Message != "" {
			return errors.New(e.Message)
		}
		return fmt.Errorf("hub returned %s: %s", resp.Status, e.Code)
	}

	return fmt.Errorf("hub returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

// hostOf is the Host header a request to this url will carry, which is part of
// what gets signed.
func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("bad hub url: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("hub url %q has no host", rawURL)
	}
	return u.Host, nil
}

// bootstrapSigners are the ssh keys that might vouch for this machine. The
// agent is preferred, so the key itself never has to be read from disk.
func bootstrapSigners(opts JoinOptions) ([]ssh.Signer, error) {
	if opts.Signer != nil {
		return []ssh.Signer{opts.Signer}, nil
	}

	// An explicit key means exactly that key, agent or no agent.
	if opts.SSHKeyPath != "" {
		signer, err := signerFromFile(opts.SSHKeyPath)
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{signer}, nil
	}

	signers, err := wrak.AgentSigners()
	if err != nil {
		return nil, fmt.Errorf("%w (robinet join signs a bootstrap message with your ssh key)", err)
	}

	if opts.SSHFingerprint != "" {
		for _, s := range signers {
			if ssh.FingerprintSHA256(s.PublicKey()) == opts.SSHFingerprint {
				return []ssh.Signer{s}, nil
			}
		}

		held := make([]string, 0, len(signers))
		for _, s := range signers {
			held = append(held, ssh.FingerprintSHA256(s.PublicKey()))
		}
		return nil, fmt.Errorf("the agent does not hold %s, it has: %s",
			opts.SSHFingerprint, strings.Join(held, ", "))
	}

	return signers, nil
}

// signerFromFile loads a private key, which is how a machine with no agent
// signs its registration.
func signerFromFile(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the ssh key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		var needsPassphrase *ssh.PassphraseMissingError
		if errors.As(err, &needsPassphrase) {
			return nil, fmt.Errorf("%s is passphrase protected, add it to an agent instead: ssh-add %s", path, path)
		}
		return nil, fmt.Errorf("could not read the ssh key: %w", err)
	}

	return signer, nil
}
