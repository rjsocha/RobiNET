package main

import "testing"

func TestAnUneditedTemplateIsRecognized(t *testing.T) {
	for _, raw := range []string{"CHANGEME", "changeme", "  CHANGEME  "} {
		if !isPlaceholder(raw) {
			t.Errorf("%q was taken for a real endpoint", raw)
		}
	}
}

// A real endpoint always has a slash, so nothing legitimate can look like the
// placeholder - including an instance somebody chose to call changeme.
func TestARealEndpointIsLeftAlone(t *testing.T) {
	for _, raw := range []string{
		"250.250.250.250/example/demo",
		"https://hub.example:8443/v1/enroll/e2063acca759f5c0",
		"hub.example.com/changeme",
	} {
		if isPlaceholder(raw) {
			t.Errorf("%q was refused", raw)
		}
	}
}
