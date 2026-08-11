package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rjsocha/robinet/internal/enroll"
	"github.com/rjsocha/robinet/internal/pin"
)

// hubClient talks to the enrollment mailbox.
type hubClient struct {
	base   string
	token  string
	client *http.Client
	log    *slog.Logger
}

// newHubClient builds the client both the enrollment and the blocklist poll
// use, so a pin given once covers everything this connector ever asks the hub.
//
// A pin wins over Insecure rather than combining with it: one names the key
// that must answer, the other says any key will do, and the stricter of the
// two is what somebody handing out a pinned endpoint meant.
func newHubClient(base, sharedToken string, insecure bool, hubPin string, log *slog.Logger) (*hubClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch {
	case hubPin != "":
		cfg, err := pin.TLSConfig(hubPin)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = cfg
	case insecure:
		// The hub's certificate is usually self signed. The enrollment payload
		// is authenticated by the shared token instead, and the certificate
		// that comes back cannot be forged by whoever carries it.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &hubClient{
		base:   strings.TrimRight(base, "/"),
		token:  sharedToken,
		client: &http.Client{Transport: transport, Timeout: 30 * time.Second},
		log:    log,
	}, nil
}

// submit posts an enrollment request and returns its id.
func (c *hubClient) submit(ctx context.Context, instance string, req enroll.Request) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/v1/enroll/"+instance, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set(enroll.MACHeader, req.MAC(c.token))
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", responseError(resp)
	}

	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("the hub returned no request id")
	}

	return out.ID, nil
}

// result asks what happened to a request.
func (c *hubClient) result(ctx context.Context, instance, id string) (*enroll.Result, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/v1/enroll/"+instance+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, responseError(resp)
	}

	var res enroll.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	return &res, nil
}

// refusedBackoff is how long the connector waits before giving up and letting
// its supervisor try again.
//
// A refusal is about the request itself - a bad domain, the wrong shared token,
// a burned key - so the next attempt will be refused the same way. Returning at
// once turns "unless-stopped" into a restart loop measured in milliseconds,
// which buries the one line saying why in its own noise.
const refusedBackoff = 30 * time.Second

// waitForApproval submits if needed and then polls until there is an answer.
// A rejection ends the wait: the operator said no, and a restart is how the
// connector asks again.
func (c *hubClient) waitForApproval(ctx context.Context, instance string, req enroll.Request, state *State) (*enroll.Bundle, error) {
	if state.RequestID == "" {
		id, err := c.submit(ctx, instance, req)
		if err != nil {
			return nil, c.refused(ctx, err)
		}
		if err := state.SaveRequestID(id); err != nil {
			return nil, err
		}
		c.log.Info("enrollment submitted, waiting for approval",
			"instance", instance,
			"request", id,
			"fingerprint", state.Fingerprint()[:16],
		)
	}

	backoff := 5 * time.Second
	for {
		res, err := c.result(ctx, instance, state.RequestID)
		if err != nil {
			c.log.Warn("could not read the enrollment result", "error", err)
		} else {
			switch res.Status {
			case enroll.StatusApproved:
				if res.Bundle == nil {
					return nil, fmt.Errorf("the hub reported approval without a certificate")
				}
				return res.Bundle, nil

			case enroll.StatusRejected:
				return nil, c.refused(ctx, fmt.Errorf("enrollment rejected: %s", res.Reason))
			}

			if res.RetryAfter > 0 {
				backoff = time.Duration(res.RetryAfter) * time.Second
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// refused holds the error for a while before handing it back, so a supervisor
// restarting the container does not spin.
func (c *hubClient) refused(ctx context.Context, err error) error {
	c.log.Error("enrollment refused, waiting before letting this process exit",
		"error", err, "wait", refusedBackoff)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(refusedBackoff):
	}

	return err
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	var e enroll.Error
	if json.Unmarshal(body, &e) == nil && e.Code != "" {
		return fmt.Errorf("hub returned %s: %w", resp.Status, &e)
	}

	return fmt.Errorf("hub returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
}
