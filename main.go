package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

var version = "undefined"

type algorithmType int

const (
	unknownAlgorithm algorithmType = iota
	rsa
	dsa
	ecdsa
	ed25519
)

type algorithm struct {
	name   algorithmType
	keylen int
}

type publickey struct {
	alg               algorithm
	fingerprintMD5    string
	fingerprintSHA256 string
	name              string
}

type unixuser struct {
	name string
	home string
}

type accessSummary struct {
	lastUse time.Time
	lastIP  net.IP
	count   int
}

// Map of user names to a map of fingerprints to accessSummary
type logSummary map[string]map[string]accessSummary

type access struct {
	user        string
	fingerprint string
	ts          time.Time
	ip          net.IP
}

type tableRow struct {
	user              string
	name              string
	alg               algorithm
	lastUse           time.Time
	count             int
	fingerprintMD5    string
	fingerprintSHA256 string
	lastIP            string
}

var logPattern = regexp.MustCompile("^([A-Za-z]+ [ 0-9][0-9] [0-9]+:[0-9]+:[0-9]+) [^ ]* sshd\\[[0-9]+\\]: " +
	"Accepted publickey for (.+) from ([0-9a-f.:]+) port [0-9]+ ssh2: [A-Z0-9\\-]+ ([0-9a-f:]+)$")

func main() {
	csv := flag.Bool("csv", false, "Print table as CSV (RFC 4180) using RFC 3339 for dates")
	enableFingerprintMD5 := flag.Bool("fingerprint", false, "Show fingerprint (MD5) column")
	enableFingerprintSHA256 := flag.Bool("fingerprint-sha256", false, "Show fingerprint (SHA256) column")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ssh-keycheck", version, runtime.Version())
		os.Exit(0)
	}

	table, err := buildKeyTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *csv {
		printCSV(table)
	} else {
		printAlignedTable(table, *enableFingerprintMD5, *enableFingerprintSHA256)
	}
}

func printAlignedTable(table []tableRow, enableFingerprintMD5 bool, enableFingerprintSHA256 bool) {
	now := time.Now()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "USER\tNAME\tTYPE\tSECURITY\tLAST USE\tCOUNT\tLAST IP")
	if enableFingerprintMD5 {
		fmt.Fprintf(w, "\tFINGERPRINT-MD5")
	}
	if enableFingerprintSHA256 {
		fmt.Fprintf(w, "\tFINGERPRINT-SHA256")
	}
	fmt.Fprintln(w)

	for _, row := range table {
		var algStr, lastUseStr, lastIPStr, countStr, insecureStr string
		if row.count > 0 {
			lastUseStr = durationAsString(now.Sub(row.lastUse))
			countStr = fmt.Sprintf("%5d", row.count)
			lastIPStr = row.lastIP
		} else {
			lastUseStr = "never"
			countStr = "    -"
			lastIPStr = "-"
		}
		if row.alg.name == rsa || row.alg.name == ecdsa {
			// RSA and ECDSA can be generated with different key lengths
			algStr = fmt.Sprintf("%s-%d", row.alg.name, row.alg.keylen)
		} else {
			// DSA and ED25519 have fixed key lengths
			algStr = row.alg.name.String()
		}
		if row.alg.isInsecure() {
			insecureStr = "insecure"
		} else {
			insecureStr = "ok"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s", row.user, row.name,
			algStr, insecureStr, lastUseStr, countStr, lastIPStr)
		if enableFingerprintMD5 {
			fmt.Fprintf(w, "\t%s", row.fingerprintMD5)
		}
		if enableFingerprintSHA256 {
			fmt.Fprintf(w, "\t%s", row.fingerprintSHA256)
		}
		fmt.Fprintln(w)
	}

	w.Flush()
}

func printCSV(table []tableRow) {
	w := csv.NewWriter(os.Stdout)
	w.Write([]string{
		"user",
		"name",
		"type",
		"keylen",
		"insecure",
		"lastuse",
		"count",
		"lastip",
		"fingerprint",
		"fingerprint_sha256",
	})

	for _, row := range table {
		lastUseStr := ""
		if row.count > 0 {
			// if the key was never used, the timestamp should not be printed
			lastUseStr = row.lastUse.Format(time.RFC3339)
		}
		w.Write([]string{
			row.user,
			row.name,
			row.alg.name.String(),
			strconv.Itoa(row.alg.keylen),
			strconv.FormatBool(row.alg.isInsecure()),
			lastUseStr,
			strconv.Itoa(row.count),
			row.lastIP,
			row.fingerprintMD5,
			row.fingerprintSHA256,
		})
	}

	w.Flush()
}

func buildKeyTable() ([]tableRow, error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var allKeys map[string][]publickey
	var allLogs logSummary
	var allKeysErr, allLogsErr error

	// Execute log file parsing and collecting authorized keys in parallel
	go func() {
		allKeys, allKeysErr = getAuthorizedKeysForAllUsers()
		wg.Done()
	}()
	go func() {
		allLogs, allLogsErr = parseAllLogFiles()
		wg.Done()
	}()

	// Wait for both goroutines to finish
	wg.Wait()

	// Check for any errors that occured
	if allKeysErr != nil {
		return nil, allKeysErr
	}
	if allLogsErr != nil {
		return nil, allLogsErr
	}

	// Sort users by name
	var usernames []string
	for k := range allKeys {
		usernames = append(usernames, k)
	}
	sort.Strings(usernames)

	var table []tableRow

	for _, user := range usernames {
		for _, key := range allKeys[user] {
			summary := allLogs[user][key.fingerprintMD5]

			table = append(table, tableRow{
				user:              user,
				name:              key.name,
				alg:               key.alg,
				lastUse:           summary.lastUse,
				count:             summary.count,
				fingerprintMD5:    key.fingerprintMD5,
				fingerprintSHA256: key.fingerprintSHA256,
				lastIP:            summary.lastIP.String(),
			})
		}
	}

	return table, nil
}

// Parse the given stream and return a list of keys, splitted into
// algorithm, pubkey and name.
// Invalid lines are ignored.
func parseAuthorizedKeys(file io.Reader) ([]publickey, error) {
	// Every public key is in its own line
	var keys []publickey
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		splits := strings.SplitN(scanner.Text(), " ", 3)
		if len(splits) != 3 {
			continue
		}

		// Public keys are always base64 encoded
		pubkey, err := base64.StdEncoding.DecodeString(splits[1])
		if err != nil {
			continue
		}

		// Don't use splits[0] because the algorithm can be extracted from
		// the pubkey
		keys = append(keys, publickey{
			alg:               parseKeyType(pubkey),
			fingerprintMD5:    fingerprintMD5(pubkey),
			fingerprintSHA256: fingerprintSHA256(pubkey),
			name:              splits[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

// Compute the MD5 fingerprint of a given public key
// The MD5 hash is hex encoded and divided into groups of two characters
// separated by colons
// e.g.: "3c:a1:90:94:fd:56:ea:92:d2:d8:3f:12:27:47:96:d3"
func fingerprintMD5(pubkey []byte) string {
	hasher := md5.New()
	hasher.Write(pubkey)
	hash := hex.EncodeToString(hasher.Sum(nil))

	var colonhash bytes.Buffer
	for pos, ch := range hash {
		colonhash.WriteRune(ch)
		if pos%2 == 1 && pos < len(hash)-1 {
			colonhash.WriteRune(':')
		}
	}
	return colonhash.String()
}

// Compute the SHA256 fingerprint of a given public key.
// The SHA256 hash is base64 encoded (Raw encoding / No padding).
// e.g.: "ijtgEqybuFNrfP777QRpiuQzhbjUaSbeqcEPXsJFqnc"
func fingerprintSHA256(pubkey []byte) string {
	hasher := sha256.New()
	hasher.Write(pubkey)
	hash := base64.RawStdEncoding.EncodeToString(hasher.Sum(nil))

	return hash
}

// Parse public key and return the algorithm's name and key length.
// Uses the splitPubkey helper function to do the actual work.
func parseKeyType(pubkey []byte) algorithm {
	name, partLengths := splitPubkey(pubkey)

	if len(partLengths) == 0 {
		return algorithm{name: unknownAlgorithm}
	}

	switch name {
	case "ssh-rsa":
		// RSA key length is determined by the length of the modulus.
		// The modulus is the third part of the parsed key
		// https://security.stackexchange.com/a/42272
		keylen := 0
		if len(partLengths) == 3 {
			// This should always be computed
			keylen = 8 * (partLengths[2] - 1)
		}
		return algorithm{
			name:   rsa,
			keylen: keylen,
		}
	case "ssh-ed25519":
		// ED25519 always uses a key length of 256 bits
		return algorithm{
			name:   ed25519,
			keylen: 256,
		}
	case "ssh-dss":
		// DSA always uses a key length of 1024 bits
		return algorithm{
			name:   dsa,
			keylen: 1024,
		}
	case "ecdsa-sha2-nistp521":
		return algorithm{
			name:   ecdsa,
			keylen: 521,
		}
	case "ecdsa-sha2-nistp384":
		return algorithm{
			name:   ecdsa,
			keylen: 384,
		}
	case "ecdsa-sha2-nistp256":
		return algorithm{
			name:   ecdsa,
			keylen: 256,
		}
	}

	return algorithm{name: unknownAlgorithm}
}

// Parses a public key and returns its first part (the name) and the lengths
// of all parts.
// A public key can be divided in one or more parts. Every part consists of
// a length field (4 bytes, big endian) and a data field. The length field
// specifies the length of the data field in bytes.
func splitPubkey(pubkey []byte) (string, []int) {
	buf := bytes.NewReader(pubkey)
	firstPart := ""
	var partLengths []int
	for {
		var length int32
		err := binary.Read(buf, binary.BigEndian, &length)
		if err != nil {
			break
		}

		data := make([]byte, length)
		n, _ := buf.Read(data)
		if int32(n) != length {
			break
		}

		if len(partLengths) == 0 {
			firstPart = string(data)
		}
		partLengths = append(partLengths, int(length))
	}

	return firstPart, partLengths
}

// Parse a log file written by sshd and return all logs with accepted logins
// using an ssh key
func parseLogFile(path string) (logSummary, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	logFileYear := info.ModTime().Year()
	logFileTimezone := info.ModTime().Location()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gr, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gr.Close()

		scanner = bufio.NewScanner(gr)
	} else {
		scanner = bufio.NewScanner(file)
	}

	logs := make(logSummary)

	for scanner.Scan() {
		line := scanner.Text()
		log, ok := parseLogLine(logFileYear, logFileTimezone, line)
		if !ok {
			continue
		}

		// create map of fingerprints if not yet there
		if logs[log.user] == nil {
			logs[log.user] = make(map[string]accessSummary)
		}

		access := logs[log.user][log.fingerprint]
		if access.lastUse.IsZero() || log.ts.After(access.lastUse) {
			access.lastUse = log.ts
			access.lastIP = log.ip
		}
		access.count++
		logs[log.user][log.fingerprint] = access
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}

func parseLogLine(year int, location *time.Location, line string) (access, bool) {
	if !strings.Contains(line, "Accepted publickey for") {
		return access{}, false
	}
	m := logPattern.FindStringSubmatch(line)
	if len(m) != 5 {
		return access{}, false
	}
	ts, err := time.ParseInLocation("2006 Jan 2 15:04:05", strconv.Itoa(year)+" "+m[1], location)
	if err != nil {
		return access{}, false
	}

	return access{
		user:        m[2],
		ip:          net.ParseIP(m[3]),
		fingerprint: m[4],
		ts:          ts,
	}, true
}

// Read /etc/passwd and return all users and their corresponding home directory
func parseAllUsers(file io.Reader) ([]unixuser, error) {
	var users []unixuser

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fs := strings.Split(scanner.Text(), ":")
		if len(fs) != 7 {
			continue
		}
		users = append(users, unixuser{name: fs[0], home: fs[5]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func getAllUsers() ([]unixuser, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseAllUsers(file)
}

// Opens ~/.ssh/authorized_keys for all users and returns
// every key parsed into algorithm, key and name in a map.
func getAuthorizedKeysForAllUsers() (map[string][]publickey, error) {
	users, err := getAllUsers()
	if err != nil {
		return nil, err
	}

	keys := make(map[string][]publickey)
	var mut sync.Mutex
	var wg sync.WaitGroup

	for _, user := range users {
		wg.Add(1)
		go func(user unixuser) {
			defer wg.Done()

			// open ~/.ssh/authorized_keys
			file, err := os.Open(path.Join(user.home, ".ssh", "authorized_keys"))
			if err != nil {
				return
			}
			defer file.Close()

			userkeys, err := parseAuthorizedKeys(file)
			if err != nil {
				return
			}

			mut.Lock()
			keys[user.name] = userkeys
			mut.Unlock()
		}(user)
	}

	wg.Wait()

	return keys, nil
}

func durationAsString(dur time.Duration) string {
	var count int
	var unit string

	if dur.Seconds() < 1 {
		return "just now"
	} else if dur.Minutes() < 1 {
		count = int(dur.Seconds())
		unit = "second"
	} else if dur.Hours() < 1 {
		count = int(dur.Minutes())
		unit = "minute"
	} else if dur.Hours() < 24 {
		count = int(dur.Hours())
		unit = "hour"
	} else {
		count = int(dur.Hours() / 24)
		unit = "day"
	}

	if count != 1 {
		// add plural 's'
		unit += "s"
	}

	return fmt.Sprintf("%d %s ago", count, unit)
}

func parseAllLogFiles() (logSummary, error) {
	allfiles, err := filepath.Glob("/var/log/auth.log*")
	if err != nil {
		return nil, err
	}

	allLogs := make(logSummary)
	var lastError error

	var mut sync.Mutex
	var wg sync.WaitGroup

	for _, file := range allfiles {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			logs, err := parseLogFile(file)

			mut.Lock()
			if err != nil {
				lastError = err
			} else {
				mergeLogs(allLogs, logs)
			}
			mut.Unlock()
		}(file)
	}

	wg.Wait()

	if lastError != nil {
		return nil, lastError
	}
	return allLogs, nil
}

func mergeLogs(target logSummary, source logSummary) {
	for user, submap := range source {
		if target[user] == nil {
			target[user] = make(map[string]accessSummary)
		}
		for fingerprint, summary := range submap {
			targetSummary := target[user][fingerprint]
			if summary.lastUse.After(targetSummary.lastUse) {
				targetSummary.lastUse = summary.lastUse
				targetSummary.lastIP = summary.lastIP
			}
			targetSummary.count += summary.count
			target[user][fingerprint] = targetSummary
		}
	}
}

// Checks if the algorithm is discouraged to be used
// DSA: https://www.gentoo.org/support/news-items/2015-08-13-openssh-weak-keys.html
// RSA: https://www.keylength.com/en/4/
// ECDSA: https://wiki.archlinux.org/index.php/SSH_keys#ECDSA
func (alg *algorithm) isInsecure() bool {
	return alg.name == dsa ||
		alg.name == ecdsa ||
		(alg.name == rsa && alg.keylen < 2048)
}

func (name algorithmType) String() string {
	switch name {
	case rsa:
		return "RSA"
	case dsa:
		return "DSA"
	case ecdsa:
		return "ECDSA"
	case ed25519:
		return "ED25519"
	}
	return "[unknown]"
}
