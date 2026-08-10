package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Placeholder is what a template carries where an endpoint belongs.
//
// One word, compared against the whole value rather than against a part of it.
// A real endpoint always has a slash in it, so nothing legitimate can ever look
// like this, and there is no list of things that might have been meant.
// Upper case because in a template it reads as a blank to fill rather than as
// the name of something.
const Placeholder = "CHANGEME"

// placeholderWait is how long a connector sits there before giving up.
//
// A platform restarts a container that exits, as fast as it exits, so a
// connector that failed instantly would fill a log with the same line hundreds
// of times and lose the one worth reading. Ten seconds makes the message the
// thing somebody sees.
const placeholderWait = 10 * time.Second

// isPlaceholder reports whether the endpoint was never filled in.
func isPlaceholder(endpoint string) bool {
	return strings.EqualFold(strings.TrimSpace(endpoint), Placeholder)
}

// refusePlaceholder says what is wrong, waits, and gives up without opening a
// connection: there is nothing to connect to, and a hub should not see traffic
// from somebody who has not been told which hub they are talking to.
func refusePlaceholder(ctx context.Context) error {
	fmt.Fprintf(os.Stdout, "robinet is not configured: ROBINET_ENDPOINT is still %s.\n", Placeholder)
	fmt.Fprintf(os.Stdout, "\nSet it to what the owner of the instance gave you:\n")
	fmt.Fprintf(os.Stdout, "\n    ROBINET_ENDPOINT=<hub>/<instance>/<token>\n")
	fmt.Fprintf(os.Stdout, "\nThey get that line from robinet instance show.\n")

	select {
	case <-ctx.Done():
	case <-time.After(placeholderWait):
	}

	return fmt.Errorf("no endpoint has been set")
}
