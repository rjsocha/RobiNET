// Package version carries the build identity.
//
// Build is set at link time. A binary built without the Makefile says "dev",
// which is honest: it was not produced by anything reproducible.
package version

// Build is overwritten with -X at link time.
var Build = "dev"

// String is what a human sees.
func String() string { return Build }

// Nebula is what a peer sees in handshake logs. Naming the role makes a log on
// the far side say which of the three sent it.
func Nebula(role string) string {
	return "robinet/" + Build + " " + role
}
