package main

import (
	"io"
	"strings"
	"testing"
)

const pubkey = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDDn9gf8cu+t4cyPw5MBhw811s8p1GR4X" +
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
const fingerprint = "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"

func TestComputeFingerprint(t *testing.T) {
	computedFingerprint := computeFingerprint(pubkey)
	if computedFingerprint != fingerprint {
		t.Errorf("Expected %s but got %s", fingerprint, computedFingerprint)
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	authorizedKeys := "ssh-rsa " + pubkey + " syxolk@github.com\n" +
		"ssh-rsa INVALIDKEY"

	var reader io.Reader = strings.NewReader(authorizedKeys)
	keys, err := parseAuthorizedKeys(&reader)

	if err != nil {
		t.Fatalf("Failed with error: %s", err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected %d but got %d keys", 1, len(keys))
	}

	if keys[0].name != "syxolk@github.com" {
		t.Errorf("Expected name %s but got %s", "syxolk@github.com",
			keys[0].name)
	}

	if keys[0].algorithm != "ssh-rsa" {
		t.Errorf("Expected algorithm %s but got %s", "ssh-rsa",
			keys[0].algorithm)
	}

	if keys[0].key != pubkey {
		t.Errorf("Wrong pubkey")
	}

	if keys[0].fingerprint != fingerprint {
		t.Errorf("Expected fingerprint %s but got %s", fingerprint,
			keys[0].fingerprint)
	}
}

func TestParseAllUsers(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"hans:x:1000:1000:Hans,,,:/home/hans:/usr/bin/zsh"

	var reader io.Reader = strings.NewReader(passwd)
	users, err := parseAllUsers(&reader)

	if err != nil {
		t.Fatalf("Failed with error: %s", err)
	}

	if len(users) != 2 {
		t.Fatalf("Expected %d but got %d users", 2, len(users))
	}

	if users[0].name != "root" {
		t.Errorf("Expected name %s but %s", "root", users[0].name)
	}

	if users[0].home != "/root" {
		t.Errorf("Expected home %s but got %s", "/root", users[0].home)
	}

	if users[1].name != "hans" {
		t.Errorf("Expected name %s but got %s", "hans", users[1].name)
	}

	if users[1].home != "/home/hans" {
		t.Errorf("Expected home %s but got %s", "/home/hans", users[1].home)
	}
}
