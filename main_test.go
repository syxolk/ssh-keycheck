package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

const pubkeyRsa4096 = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDDn9gf8cu+t4cyPw5MBhw811s8p1GR4X" +
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
const fingerprintRsa4096 = "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"

const pubkeyDsa = "AAAAB3NzaC1kc3MAAACBALyk040uIm96YRrfhStAGvA+oB9pCyJxUyDLFA" +
	"xZvonOKJaTmFv6j+ZVgUYg1p+MSGGoO0CLzg5x7LJriLpvZVMBiiaPB/65Xd58a1AGGozIjL" +
	"hI3k7caviQDEvsOilf+63t4dfL8zV76O59jxqFTQrgyucDGxmgyNog1U+zWDTXAAAAFQCzqn" +
	"pvRpCDUxvrFG5Rs4adBXMVBQAAAIEAm6w3yAWcCWJxt4cPAidwFyf5/nOduzI2DmuFGLupEK" +
	"VY4LlI8luNyTcBxxE3rdyeF0wuI7Ssoma8sib4u1NLA1QDMzXTpqP2sKZiAWkgh0h4neHwQz" +
	"XZD6vDJmKuJ95BavLQrQaxlSjjgbvlJoVPWhRBbWW//5qG/w4UqrsnwMcAAACBALGGFn3chw" +
	"/iQOIQAzKDyBm3iYvTB6ZoxxRRIx5H6hpXKSnki1QG2m7B25WTxgJy+DdEoBhIe74G0Q4eB3" +
	"ExJLS1G+mBd11IRJNpl8F7Ai46Sqdg3rqlghR6abPGMtS8VqDY/aQyO63yyUQjYvL+KiFKTM" +
	"Qgf9WpltBpP2rg0BDO"
const fingerprintDsa = "b9:e9:3c:2b:e7:47:87:35:4e:b4:ab:28:5d:b0:dd:03"

const pubkeyEcdsa256 = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB" +
	"MgN/2nqDTX0qap9CbHHmteo7Dwe3Mu6HrHdCcm89bMtCKHpt8SBfSmFkC+TYS4ogmrdXWax5" +
	"US01YAlcrVyahI="
const fingerprintEcdsa256 = "b0:3a:37:c0:99:09:b0:e4:a1:9f:9f:fb:de:18:a5:56"

const pubkeyEcdsa384 = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhB" +
	"Psih9oUCd46Fx4QdlnB7qsv5rpGzYLJQkax6Dm3zJK4etK6XCzbujiGZmrKmYVw/SRAEnXsJ" +
	"KsEflg1spEGNCfrBB/OtB93RDz6mzSMmouJfXeidYjI1VMtZVVJY59DbQ=="
const fingerprintEcdsa384 = "fc:16:56:45:33:1b:e5:71:45:c4:88:7d:b9:2d:8a:b9"

const pubkeyEcdsa521 = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFB" +
	"AEflOtqKirwjX6jISdWOTLlgq7ELAcC+wQMNoO0d+XmaIlgKtRo4rrTHZYrZUdTnYLZXWcZs" +
	"Vay8SogT1MEE5sqowG/NFMo+ntjTbloUzIXXyyfU/owI939bOmSCrttWd6lDQ24y1ZXFi+Sg" +
	"Ymks8rhruGNTv0quXWgC5bVcNQLH0Egig=="
const fingerprintEcdsa521 = "58:b4:2c:c4:a6:48:11:aa:4b:c9:29:6f:f9:b4:db:ba"

const pubkeyEd25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIDTOl+HDVEDrNXcm2Azxjw3/VZNith" +
	"2iUEm7wWpHZLzE"
const fingerprintEd25519 = "b7:32:01:5c:78:97:b1:3f:4d:bd:98:56:d0:33:61:3a"

func TestComputeFingerprint(t *testing.T) {
	parameters := []struct {
		pubkey      string
		fingerprint string
	}{
		{pubkeyRsa4096, fingerprintRsa4096},
		{pubkeyDsa, fingerprintDsa},
		{pubkeyEcdsa256, fingerprintEcdsa256},
		{pubkeyEcdsa384, fingerprintEcdsa384},
		{pubkeyEcdsa521, fingerprintEcdsa521},
		{pubkeyEd25519, fingerprintEd25519},
	}

	for _, p := range parameters {
		f := computeFingerprint(p.pubkey)
		if f != p.fingerprint {
			t.Errorf("Expected %s but got %s", p.fingerprint, f)
		}
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	authorizedKeys := "ssh-rsa " + pubkeyRsa4096 + " syxolk@github.com\n" +
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

	if keys[0].alg.name != "RSA" {
		t.Errorf("Expected algorithm %s but got %s", "RSA",
			keys[0].alg.name)
	}

	if keys[0].alg.keylen != 4096 {
		t.Errorf("Expected keylen %d but got %d", 4096, keys[0].alg.keylen)
	}

	if keys[0].fingerprint != fingerprintRsa4096 {
		t.Errorf("Expected fingerprint %s but got %s", fingerprintRsa4096,
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

func TestDurationAsString(t *testing.T) {
	parameters := []struct {
		in  time.Duration
		out string
	}{
		{12 * time.Second, "just now"},
		{1 * time.Minute, "1 minute ago"},
		{2 * time.Minute, "2 minutes ago"},
		{1 * time.Hour, "1 hour ago"},
		{2 * time.Hour, "2 hours ago"},
		{24 * time.Hour, "1 day ago"},
		{48 * time.Hour, "2 days ago"},
		{192 * time.Hour, "8 days ago"},
	}

	for _, p := range parameters {
		g := durationAsString(p.in)
		if g != p.out {
			t.Errorf("Expected %s but got %s", p.out, g)
		}
	}
}

func TestParseKeyType(t *testing.T) {
	keys := []struct {
		pubkey string
		name   string
		keylen int
	}{
		{pubkeyRsa4096, "RSA", 4096},
		{pubkeyDsa, "DSA", 1024},
		{pubkeyEcdsa256, "ECDSA", 256},
		{pubkeyEcdsa384, "ECDSA", 384},
		{pubkeyEcdsa521, "ECDSA", 521},
		{pubkeyEd25519, "ED25519", 256},
	}

	for _, k := range keys {
		c := parseKeyType(k.pubkey)
		if c.name != k.name {
			t.Errorf("Expected %s but got %s", k.name, c.name)
		}
		if c.keylen != k.keylen {
			t.Errorf("Expected %s keylen %d but got %d", k.name, k.keylen, c.keylen)
		}
	}

}
