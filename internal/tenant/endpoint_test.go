package tenant

import "testing"

// One string is what somebody pastes into a platform's environment, so
// everything a connector needs has to be in it, and the parts that are absent
// have to leave no gap behind.
func TestTheEndpointCarriesWhateverThereIs(t *testing.T) {
	const hub = "https://192.0.2.10:8443"
	const hubPin = "SHA256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

	cases := []struct {
		token string
		pin   string
		want  string
	}{
		{want: "192.0.2.10/railway-prod"},
		{token: "sekret", want: "192.0.2.10/railway-prod/sekret"},
		{pin: hubPin, want: "192.0.2.10/railway-prod/" + hubPin},
		{token: "sekret", pin: hubPin, want: "192.0.2.10/railway-prod/sekret/" + hubPin},
	}

	for _, c := range cases {
		if got := shorthandEndpoint(hub, "railway-prod", c.token, c.pin); got != c.want {
			t.Errorf("token %q pin %q gave %q, want %q", c.token, c.pin, got, c.want)
		}
	}

	// A hub on another port keeps it, since a connector assumes the default
	// one and would otherwise knock on the wrong door.
	if got := shorthandEndpoint("https://192.0.2.10:9443", "abc", "", hubPin); got != "192.0.2.10:9443/abc/"+hubPin {
		t.Errorf("a non default port gave %q", got)
	}
}
