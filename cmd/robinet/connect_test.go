package main

import "testing"

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		base     string
		instance string
		token    string
		wantErr  bool
	}{
		{in: "192.0.2.10/76615289c33b3186",
			base: "https://192.0.2.10:8443", instance: "76615289c33b3186"},
		{in: "192.0.2.10/76615289c33b3186/sekret",
			base: "https://192.0.2.10:8443", instance: "76615289c33b3186", token: "sekret"},
		{in: "192.0.2.10:9443/abc",
			base: "https://192.0.2.10:9443", instance: "abc"},
		{in: "hub.example.com/abc",
			base: "https://hub.example.com:8443", instance: "abc"},
		{in: "https://hub.example.com:8443/v1/enroll/xyz",
			base: "https://hub.example.com:8443", instance: "xyz"},
		// A bare url still works; the instance then comes from its own flag.
		{in: "https://hub.example.com:8443", base: "https://hub.example.com:8443"},
		{in: "", base: ""},
		{in: "nonsense", wantErr: true},
		{in: "a/b/c/d", wantErr: true},
		{in: "https://hub.example.com/v1/enroll/", wantErr: true},
	}

	for _, c := range cases {
		base, instance, token, err := parseEndpoint(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q was accepted, want an error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %s", c.in, err)
			continue
		}
		if base != c.base || instance != c.instance || token != c.token {
			t.Errorf("%q gave (%q, %q, %q), want (%q, %q, %q)",
				c.in, base, instance, token, c.base, c.instance, c.token)
		}
	}
}
