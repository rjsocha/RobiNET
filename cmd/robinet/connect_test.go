package main

import "testing"

// A pin long enough to be real, in the notation an endpoint carries.
const testPin = "SHA256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		base     string
		instance string
		token    string
		pin      string
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

		// Both trailing parts are optional, so a pin has to be recognized
		// rather than located.
		{in: "192.0.2.10/abc/sekret/" + testPin,
			base: "https://192.0.2.10:8443", instance: "abc", token: "sekret", pin: testPin},
		{in: "192.0.2.10/abc/" + testPin,
			base: "https://192.0.2.10:8443", instance: "abc", pin: testPin},
		// The prefix is written however somebody copied it.
		{in: "192.0.2.10/abc/sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
			base: "https://192.0.2.10:8443", instance: "abc",
			pin: "sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"},

		// A token that happens to be as long as a pin is still a token: what
		// it is is said, not measured.
		{in: "192.0.2.10/abc/47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
			base: "https://192.0.2.10:8443", instance: "abc",
			token: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"},

		// A pin that is not a pin is a mistake in the endpoint, not something
		// to carry to the handshake and fail there.
		{in: "192.0.2.10/abc/SHA256:tooshort", wantErr: true},
		{in: "192.0.2.10/abc/" + testPin + "/" + testPin, wantErr: true},
		{in: "192.0.2.10/abc/one/two/" + testPin, wantErr: true},
	}

	for _, c := range cases {
		base, instance, token, hubPin, err := parseEndpoint(c.in)
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
		if base != c.base || instance != c.instance || token != c.token || hubPin != c.pin {
			t.Errorf("%q gave (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				c.in, base, instance, token, hubPin, c.base, c.instance, c.token, c.pin)
		}
	}
}
