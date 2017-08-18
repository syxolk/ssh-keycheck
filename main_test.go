package main

import "testing"

func TestComputeFingerprint(t *testing.T) {
	pubkey := "AAAAB3NzaC1yc2EAAAADAQABAAACAQDDn9gf8cu+t4cyPw5MBhw811s8p1GR4X" +
		"GRV+ysnIOUl/bzSMcgXKpxPAASEhtBF9MfGaPongDNvQUHS5L83EUXJyF742BjDpeVMh" +
		"x2cz5nGJcdOtFMyZGmCnNQMPv33j8bUvLm37Klj6KR1uHBfsxz127nlSWBVAGcI1ZaxB" +
		"FkZZCPuWVVTk35hb8lKKVLtPn674qAYM04xzbvUbvPMkKGyLJyRIF/nICuwUgGir9sEp" +
		"mTUXasLqtiX8k+1F+pYS9MTjD29cvKavXPCfSeY/0UxVhJDPPtuRJrdwDy0F0+ugL+tG" +
		"P7pyXUE9jdu6ek9GS9jiNonVyQzucYlOC8OqVLoled5NDXrcX9emeiqBFmV+wJKUFW5D" +
		"WHQgZByLr/hraM12yv5Dw1nJoVlG44XM5uIo3aXTFAgWPbCvJBNbzS2nbHdyyaLf6Ra+" +
		"WVC2coA8NB93tYteJDOwmJr9Wnpj4kOrbr+nhlXjrjtD8PjAcC6q22EToVJabsK+dr46" +
		"Y9Ocm7IGAz1u/ZqKnJXIDTlqtl7JqJSjQjod/hPx8jx3L5Io04oQKsoK+ReaAJQtU/Cv" +
		"BK29GkF/mJGYEqRV1dvMTEO7PjIGegX237qegIdrKoIMKD1x0t2m7/r/+IFpu3Ztjl3y" +
		"aRdw0cIrz7o/Vow6PyTHgEc74L2vE1ZtR2F8O1Vw=="
	fingerprint := "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"

	computedFingerprint := computeFingerprint(pubkey)
	if computedFingerprint != fingerprint {
		t.Errorf("Expected %s but got %s", fingerprint, computedFingerprint)
	}
}
