package main

import (
	"encoding/base64"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

const pubkeyRsa4096 = "AAAAB3NzaC1yc2EAAAADAQABAAACAQDDn9gf8cu+t4cyPw5MBhw811" +
	"s8p1GR4XGRV+ysnIOUl/bzSMcgXKpxPAASEhtBF9MfGaPongDNvQUHS5L83EUXJyF742BjDp" +
	"eVMhx2cz5nGJcdOtFMyZGmCnNQMPv33j8bUvLm37Klj6KR1uHBfsxz127nlSWBVAGcI1ZaxB" +
	"FkZZCPuWVVTk35hb8lKKVLtPn674qAYM04xzbvUbvPMkKGyLJyRIF/nICuwUgGir9sEp" +
	"mTUXasLqtiX8k+1F+pYS9MTjD29cvKavXPCfSeY/0UxVhJDPPtuRJrdwDy0F0+ugL+tG" +
	"P7pyXUE9jdu6ek9GS9jiNonVyQzucYlOC8OqVLoled5NDXrcX9emeiqBFmV+wJKUFW5D" +
	"WHQgZByLr/hraM12yv5Dw1nJoVlG44XM5uIo3aXTFAgWPbCvJBNbzS2nbHdyyaLf6Ra+" +
	"WVC2coA8NB93tYteJDOwmJr9Wnpj4kOrbr+nhlXjrjtD8PjAcC6q22EToVJabsK+dr46" +
	"Y9Ocm7IGAz1u/ZqKnJXIDTlqtl7JqJSjQjod/hPx8jx3L5Io04oQKsoK+ReaAJQtU/Cv" +
	"BK29GkF/mJGYEqRV1dvMTEO7PjIGegX237qegIdrKoIMKD1x0t2m7/r/+IFpu3Ztjl3y" +
	"aRdw0cIrz7o/Vow6PyTHgEc74L2vE1ZtR2F8O1Vw=="
const fingerprintRsa4096 = "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"
const fingerprintSHA256Rsa4096 = "ijtgEqybuFNrfP777QRpiuQzhbjUaSbeqcEPXsJFqnc"

const pubkeyRsa2048 = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDI7qrtsJtU0M3LLl4XTSmo56" +
	"A78aGLFT6WtQz5TYOjy7HM2C03wvWAsMYtXq4GYvjMyIygOiFe+LwjXZjLlFZIyqEDZdgP4P" +
	"DA/D9rjJ4G8WvV0ILOdeLB8cUKQ9FIxJ18onfP6bKoUDJvuHHazhvCHLclZQMn2n+WCPRLOf" +
	"kg9AYLhk1ytZEmC+3Eu5JIbEg34dd1o9BYQdY7ynK11/m/2JrSBeXWuR9/3kRK2OJB468gxm" +
	"oSXmyCIrrh3EObOlhZevjXrSJ5noggif1YkfEiTkA0PaNJRxIb5MS1otZ4xCPV3rMq+LBCbC" +
	"rMJykaxZxBmrcYyHRegXwDEbu/dfyx"
const fingerprintRsa2048 = "3f:96:4d:01:7e:43:a8:09:40:29:4b:e4:28:6a:e1:21"
const fingerprintSHA256Rsa2048 = "VmyFUZbo/kpCuG28EyR463w/Wl+1SkRfI+1oeCmwvc0"

const pubkeyRsa1024 = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCwxotwPF22gFU0jpFBCY+n2n" +
	"Cx00bd5nMIKYc+w7SjrWghY9z/pgWUQPZJ74lplnehyLyBx2RroGgHkUhAzQ0ud41if+8+Xi" +
	"T/cKoxQ1sBRAeFDCchwaHxf8HDZOw6bARJzkmhUpMvw7ZaEaCLseNHkc0FAbPHuYrN6xCCiz" +
	"J9tQ=="
const fingerprintRsa1024 = "e6:96:4f:57:3a:65:d9:f5:23:bb:56:5a:03:27:86:8d"
const fingerprintSHA256Rsa1024 = "F+TENUvs5TAmRYHDb4DA4nRaD40APli0nOCsL8hskBE"

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
const fingerprintSHA256Dsa = "3bLWcIqMtaj8oGVGw3LPCyed1y2kXjXj2oINCahL/ME"

const pubkeyEcdsa256 = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB" +
	"MgN/2nqDTX0qap9CbHHmteo7Dwe3Mu6HrHdCcm89bMtCKHpt8SBfSmFkC+TYS4ogmrdXWax5" +
	"US01YAlcrVyahI="
const fingerprintEcdsa256 = "b0:3a:37:c0:99:09:b0:e4:a1:9f:9f:fb:de:18:a5:56"
const fingerprintSHA256Ecdsa256 = "Gz0UeVhLA4DHQMlK+Ru0cSsWAA03RxNouMiZrE31Bd8"

const pubkeyEcdsa384 = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhB" +
	"Psih9oUCd46Fx4QdlnB7qsv5rpGzYLJQkax6Dm3zJK4etK6XCzbujiGZmrKmYVw/SRAEnXsJ" +
	"KsEflg1spEGNCfrBB/OtB93RDz6mzSMmouJfXeidYjI1VMtZVVJY59DbQ=="
const fingerprintEcdsa384 = "fc:16:56:45:33:1b:e5:71:45:c4:88:7d:b9:2d:8a:b9"
const fingerprintSHA256Ecdsa384 = "loP2THC86Gf2cGyfZ98GpU8Cz/63XlkPF/5bqnQxabw"

const pubkeyEcdsa521 = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFB" +
	"AEflOtqKirwjX6jISdWOTLlgq7ELAcC+wQMNoO0d+XmaIlgKtRo4rrTHZYrZUdTnYLZXWcZs" +
	"Vay8SogT1MEE5sqowG/NFMo+ntjTbloUzIXXyyfU/owI939bOmSCrttWd6lDQ24y1ZXFi+Sg" +
	"Ymks8rhruGNTv0quXWgC5bVcNQLH0Egig=="
const fingerprintEcdsa521 = "58:b4:2c:c4:a6:48:11:aa:4b:c9:29:6f:f9:b4:db:ba"
const fingerprintSHA256Ecdsa521 = "TTCk17hNFxJwsbezGRWcr4/53KcaA9Vjck70jZrJoNk"

const pubkeyEd25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIDTOl+HDVEDrNXcm2Azxjw3/VZNith" +
	"2iUEm7wWpHZLzE"
const fingerprintEd25519 = "b7:32:01:5c:78:97:b1:3f:4d:bd:98:56:d0:33:61:3a"
const fingerprintSHA256Ed25519 = "dqnPmznV1WeYUTUo+ZRBoaZzgbo1H30rqbk1MyiQsB4"

func TestComputeFingerprint(t *testing.T) {
	parameters := []struct {
		pubkey            string
		fingerprintMD5    string
		fingerprintSHA256 string
	}{
		{pubkeyRsa1024, fingerprintRsa1024, fingerprintSHA256Rsa1024},
		{pubkeyRsa2048, fingerprintRsa2048, fingerprintSHA256Rsa2048},
		{pubkeyRsa4096, fingerprintRsa4096, fingerprintSHA256Rsa4096},
		{pubkeyDsa, fingerprintDsa, fingerprintSHA256Dsa},
		{pubkeyEcdsa256, fingerprintEcdsa256, fingerprintSHA256Ecdsa256},
		{pubkeyEcdsa384, fingerprintEcdsa384, fingerprintSHA256Ecdsa384},
		{pubkeyEcdsa521, fingerprintEcdsa521, fingerprintSHA256Ecdsa521},
		{pubkeyEd25519, fingerprintEd25519, fingerprintSHA256Ed25519},
	}

	for _, p := range parameters {
		k, err := base64.StdEncoding.DecodeString(p.pubkey)
		if err != nil {
			t.Errorf("Could not decode pubkey %s", p.pubkey)
			continue
		}

		md5 := fingerprintMD5(k)
		if md5 != p.fingerprintMD5 {
			t.Errorf("Expected MD5 %s but got %s", p.fingerprintMD5, md5)
		}

		sha256 := fingerprintSHA256(k)
		if sha256 != p.fingerprintSHA256 {
			t.Errorf("Expected SHA256 %s but got %s", p.fingerprintSHA256, sha256)
		}
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	authorizedKeys := "ssh-rsa " + pubkeyRsa4096 + " syxolk@github.com\n" +
		"ssh-rsa INVALIDKEY"

	var reader io.Reader = strings.NewReader(authorizedKeys)
	keys, err := parseAuthorizedKeys(reader)

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

	if keys[0].alg.name != rsa {
		t.Errorf("Expected algorithm %s but got %s", "RSA",
			keys[0].alg.name)
	}

	if keys[0].alg.keylen != 4096 {
		t.Errorf("Expected keylen %d but got %d", 4096, keys[0].alg.keylen)
	}

	if keys[0].fingerprintMD5 != fingerprintRsa4096 {
		t.Errorf("Expected fingerprint (MD5) %s but got %s", fingerprintRsa4096,
			keys[0].fingerprintMD5)
	}

	if keys[0].fingerprintSHA256 != fingerprintSHA256Rsa4096 {
		t.Errorf("Expected fingerprint (SHA256) %s but got %s", fingerprintSHA256Rsa4096,
			keys[0].fingerprintSHA256)
	}
}

func TestParseAllUsers(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"hans:x:1000:1000:Hans,,,:/home/hans:/usr/bin/zsh"

	var reader io.Reader = strings.NewReader(passwd)
	users, err := parseAllUsers(reader)

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
		{999 * time.Millisecond, "just now"},
		{12 * time.Second, "12 seconds ago"},
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
	parameters := []struct {
		pubkey string
		name   algorithmType
		keylen int
	}{
		{pubkeyRsa1024, rsa, 1024},
		{pubkeyRsa2048, rsa, 2048},
		{pubkeyRsa4096, rsa, 4096},
		{pubkeyDsa, dsa, 1024},
		{pubkeyEcdsa256, ecdsa, 256},
		{pubkeyEcdsa384, ecdsa, 384},
		{pubkeyEcdsa521, ecdsa, 521},
		{pubkeyEd25519, ed25519, 256},
	}

	for _, p := range parameters {
		k, err := base64.StdEncoding.DecodeString(p.pubkey)
		if err != nil {
			t.Errorf("Could not decode pubkey %s", p.pubkey)
			continue
		}

		c := parseKeyType(k)
		if c.name != p.name {
			t.Errorf("Expected %s but got %s", p.name, c.name)
		}
		if c.keylen != p.keylen {
			t.Errorf("Expected %s keylen %d but got %d", p.name, p.keylen, c.keylen)
		}
	}

}

func TestParseLogLine(t *testing.T) {
	utc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("Could not load UTC")
	}

	rsaLine := "Aug 20 12:59:13 vserver sshd[12345]: " +
		"Accepted publickey for root from 127.0.0.1 port 44152 ssh2: " +
		"RSA 3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"

	line, ok := parseLogLine(2017, utc, rsaLine)
	if !ok {
		t.Fatal("Failed to parse log line")
	}

	if line.fingerprint != "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3" {
		t.Errorf("Expected %s but go %s",
			"3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3",
			line.fingerprint)
	}

	if !line.ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("Expected %s but got %s", "127.0.0.1", line.ip)
	}

	if line.user != "root" {
		t.Errorf("Expected %s but got %s", "root", line.user)
	}

	expectedTime := time.Date(2017, 8, 20, 12, 59, 13, 0, utc)
	if !line.ts.Equal(expectedTime) {
		t.Errorf("Expected %s but got %s", expectedTime, line.ts)
	}

	connectionLine := "Sep 10 06:40:50 vserver sshd[12345]: " +
		"Connection from 100.200.30.130 port 55339 on 180.60.50.150 port 22"

	_, ok = parseLogLine(2017, utc, connectionLine)
	if ok {
		t.Fatal("Successfully parsed log line but expected to fail")
	}
}

func TestMergeLogs(t *testing.T) {
	utc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal("Could not load UTC")
	}

	target := map[string]map[string]accessSummary{
		"root": {
			"aa:bb": accessSummary{
				lastUse: time.Date(2017, 9, 23, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 1),
				count:   1,
			},
			"cc:dd": accessSummary{
				lastUse: time.Date(2017, 9, 20, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 2),
				count:   5,
			},
		},
	}

	source := map[string]map[string]accessSummary{
		"root": {
			"aa:bb": accessSummary{
				lastUse: time.Date(2017, 9, 12, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 1),
				count:   1,
			},
			"cc:dd": accessSummary{
				lastUse: time.Date(2017, 9, 21, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 3),
				count:   3,
			},
		},
		"deploy": {
			"ee:ff": accessSummary{
				lastUse: time.Date(2017, 9, 12, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 4),
				count:   2,
			},
		},
	}

	expectedTarget := map[string]map[string]accessSummary{
		"root": {
			"aa:bb": accessSummary{
				lastUse: time.Date(2017, 9, 23, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 1),
				count:   2,
			},
			"cc:dd": accessSummary{
				lastUse: time.Date(2017, 9, 21, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 3),
				count:   8,
			},
		},
		"deploy": {
			"ee:ff": accessSummary{
				lastUse: time.Date(2017, 9, 12, 12, 0, 0, 0, utc),
				lastIP:  net.IPv4(10, 0, 0, 4),
				count:   2,
			},
		},
	}

	mergeLogs(target, source)

	if !reflect.DeepEqual(target, expectedTarget) {
		t.Errorf("Expected %#v\n but got %#v", expectedTarget, target)
	}
}

func TestIsInsecure(t *testing.T) {
	parameters := []struct {
		pubkey   string
		insecure bool
	}{
		{pubkeyRsa1024, true},
		{pubkeyRsa2048, false},
		{pubkeyRsa4096, false},
		{pubkeyDsa, true},
		{pubkeyEcdsa256, true},
		{pubkeyEcdsa384, true},
		{pubkeyEcdsa521, true},
		{pubkeyEd25519, false},
	}

	for _, p := range parameters {
		k, err := base64.StdEncoding.DecodeString(p.pubkey)
		if err != nil {
			t.Errorf("Could not decode pubkey %s", p.pubkey)
			continue
		}

		c := parseKeyType(k)
		insecure := c.isInsecure()
		if insecure != p.insecure {
			t.Errorf("Expected %t but got %t for %s-%d", p.insecure, insecure,
				c.name, c.keylen)
		}
	}
}
