package wrak

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// BootstrapNamespace binds a bootstrap signature to this purpose. A signature
// made with the same key for anything else will not verify here.
const BootstrapNamespace = "wrak-bootstrap-v1"

// Bootstrap is what an ssh key signs to prove a machine may enroll at all.
//
// The token appears in the signed text but never on the wire: both sides know
// it from their own configuration, so a signature is worthless to anyone who
// captures it without knowing the token.
type Bootstrap struct {
	API      string
	Token    string
	Name     string
	Identity string
}

// Message renders the exact text that gets signed.
func (b Bootstrap) Message() []byte {
	var s strings.Builder

	s.WriteString("wrak/v1/bootstrap\n")
	s.WriteString("api=" + strings.ToLower(b.API) + "\n")
	s.WriteString("registry_token=" + b.Token + "\n")
	s.WriteString("name=" + b.Name + "\n")
	s.WriteString("identity=" + b.Identity + "\n")

	return []byte(s.String())
}

// Sign produces an armored SSHSIG signature over the bootstrap message.
func (b Bootstrap) Sign(signer Signer) ([]byte, error) {
	return SignSSHSIG(signer, BootstrapNamespace, b.Message())
}

// Verify replays the message from what the verifier already knows and checks
// the signature against a set of authorized keys.
//
// Nothing from the request is trusted while building the message: the token
// comes from local configuration, so a caller cannot choose what they signed.
func (b Bootstrap) Verify(armored []byte, authorized []ssh.PublicKey) (ssh.PublicKey, error) {
	key, err := VerifySSHSIG(armored, b.Message(), BootstrapNamespace)
	if err != nil {
		return nil, err
	}

	for _, candidate := range authorized {
		if SameKey(key, candidate) {
			return key, nil
		}
	}

	return nil, fmt.Errorf("signature is valid but the key is not authorized")
}

// AgentSigners returns the keys held by the running ssh-agent.
//
// The agent signs without ever revealing the key, which is the point: nothing
// on this machine has to hold a copy, and a yubikey or a forwarded agent works
// the same way.
func AgentSigners() ([]Signer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("no ssh-agent: SSH_AUTH_SOCK is not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("could not reach the ssh-agent: %w", err)
	}

	keys, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("could not list agent keys: %w", err)
	}
	if len(keys) == 0 {
		conn.Close()
		return nil, fmt.Errorf("the ssh-agent holds no keys, add one with ssh-add")
	}

	signers := make([]Signer, 0, len(keys))
	for _, k := range keys {
		signers = append(signers, k)
	}

	return signers, nil
}

// SignerFor picks the agent key matching a public key in authorized_keys form,
// or the only key when none is named.
func SignerFor(signers []Signer, authorizedKey string) (Signer, error) {
	if strings.TrimSpace(authorizedKey) == "" {
		if len(signers) == 1 {
			return signers[0], nil
		}
		return nil, fmt.Errorf("the agent holds %d keys, say which one to use", len(signers))
	}

	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, fmt.Errorf("could not read the requested key: %w", err)
	}

	for _, s := range signers {
		if SameKey(s.PublicKey(), want) {
			return s, nil
		}
	}

	return nil, fmt.Errorf("the agent does not hold %s", AuthorizedKey(want))
}

// ParseAuthorizedKeys reads a list of keys as they appear in configuration.
func ParseAuthorizedKeys(entries []string) ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry))
		if err != nil {
			return nil, fmt.Errorf("could not read authorized key %q: %w", entry, err)
		}
		out = append(out, key)
	}

	return out, nil
}
