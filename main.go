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
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

var version = "undefined"

type algorithm struct {
	name   string
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
	lastIP  string
	count   int
}

type access struct {
	user        string
	fingerprint string
	ts          time.Time
	ip          string
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
	fmt.Fprintf(w, "USER\tNAME\tTYPE\tLAST USE\tCOUNT\tLAST IP")
	if enableFingerprintMD5 {
		fmt.Fprintf(w, "\tFINGERPRINT-MD5")
	}
	if enableFingerprintSHA256 {
		fmt.Fprintf(w, "\tFINGERPRINT-SHA256")
	}
	fmt.Fprintln(w)

	for _, row := range table {
		var algStr, lastUseStr, lastIPStr, countStr string
		if row.count > 0 {
			lastUseStr = durationAsString(now.Sub(row.lastUse))
			countStr = fmt.Sprintf("%5d", row.count)
			lastIPStr = row.lastIP
		} else {
			lastUseStr = "never"
			countStr = "    -"
			lastIPStr = "-"
		}
		if row.alg.name == "RSA" || row.alg.name == "ECDSA" {
			// RSA and ECDSA can be generated with different key lengths
			algStr = fmt.Sprintf("%s-%d", row.alg.name, row.alg.keylen)
		} else {
			// DSA and ED25519 have fixed key lengths
			algStr = row.alg.name
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s", row.user, row.name,
			algStr, lastUseStr, countStr, lastIPStr)
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
			row.alg.name,
			strconv.Itoa(row.alg.keylen),
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
	allkeys, err := getAuthorizedKeysForAllUsers()
	if err != nil {
		return nil, err
	}

	logs, err := parseAllLogFiles()
	if err != nil {
		return nil, err
	}

	// sort users by name
	var usernames []string
	for k := range allkeys {
		usernames = append(usernames, k)
	}
	sort.Strings(usernames)

	var table []tableRow

	for _, user := range usernames {
		for _, key := range allkeys[user] {
			summary := logs[user][key.fingerprintMD5]

			table = append(table, tableRow{
				user:              user,
				name:              key.name,
				alg:               key.alg,
				lastUse:           summary.lastUse,
				count:             summary.count,
				fingerprintMD5:    key.fingerprintMD5,
				fingerprintSHA256: key.fingerprintSHA256,
				lastIP:            summary.lastIP,
			})
		}
	}

	return table, nil
}

// Parse the given stream and return a list of keys, splitted into
// algorithm, pubkey and name.
// Invalid lines are ignored.
func parseAuthorizedKeys(file *io.Reader) ([]publickey, error) {
	// every public key is in its own line
	var keys []publickey
	scanner := bufio.NewScanner(*file)
	for scanner.Scan() {
		splits := strings.SplitN(scanner.Text(), " ", 3)
		if len(splits) != 3 {
			continue
		}
		keys = append(keys, publickey{
			alg:               parseKeyType(splits[1]),
			fingerprintMD5:    fingerprintMD5(splits[1]),
			fingerprintSHA256: fingerprintSHA256(splits[1]),
			name:              splits[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func fingerprintMD5(pubkey string) string {
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return ""
	}

	hasher := md5.New()
	hasher.Write(pubkeyBytes)
	hash := hex.EncodeToString(hasher.Sum(nil))

	var colonhash bytes.Buffer
	for pos, ch := range hash {
		colonhash.WriteRune(ch)
		if pos%2 == 1 && pos < len(hash)-1 {
			colonhash.WriteString(":")
		}
	}
	return colonhash.String()
}

func fingerprintSHA256(pubkey string) string {
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return ""
	}

	hasher := sha256.New()
	hasher.Write(pubkeyBytes)
	hash := base64.RawStdEncoding.EncodeToString(hasher.Sum(nil))

	return hash
}

func parseKeyType(pubkey string) algorithm {
	name, partLengths, err := splitPubkey(pubkey)
	if err != nil {
		return algorithm{name: "error"}
	}

	if len(partLengths) == 0 {
		return algorithm{name: "error"}
	}

	switch name {
	case "ssh-rsa":
		keylen := 0
		if len(partLengths) == 3 {
			// This should always be computed
			keylen = 8 * (partLengths[2] - 1)
		}
		return algorithm{
			name:   "RSA",
			keylen: keylen,
		}
	case "ssh-ed25519":
		return algorithm{
			name:   "ED25519",
			keylen: 256,
		}
	case "ssh-dss":
		return algorithm{
			name:   "DSA",
			keylen: 1024,
		}
	case "ecdsa-sha2-nistp521":
		return algorithm{
			name:   "ECDSA",
			keylen: 521,
		}
	case "ecdsa-sha2-nistp384":
		return algorithm{
			name:   "ECDSA",
			keylen: 384,
		}
	case "ecdsa-sha2-nistp256":
		return algorithm{
			name:   "ECDSA",
			keylen: 256,
		}
	}

	return algorithm{name: "unknown"}
}

func splitPubkey(pubkey string) (string, []int, error) {
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return "", nil, err
	}

	buf := bytes.NewReader(pubkeyBytes)
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

	return firstPart, partLengths, nil
}

// Parse a log file written by sshd and return all logs with accepted logins
// using an ssh key
func parseLogFile(path string) (map[string]map[string]accessSummary, error) {
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

	logs := make(map[string]map[string]accessSummary)

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
		ip:          m[3],
		fingerprint: m[4],
		ts:          ts,
	}, true
}

// Read /etc/passwd and return all users and their corresponding home directory
func parseAllUsers(file *io.Reader) ([]unixuser, error) {
	var users []unixuser

	scanner := bufio.NewScanner(*file)
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

	var reader io.Reader = file
	return parseAllUsers(&reader)
}

// Opens ~/.ssh/authorized_keys for all users and returns
// every key parsed into algorithm, key and name in a map.
func getAuthorizedKeysForAllUsers() (map[string][]publickey, error) {
	users, err := getAllUsers()
	if err != nil {
		return nil, err
	}

	type result struct {
		user string
		keys []publickey
		ok   bool
	}

	c := make(chan result)

	for _, user := range users {
		go func(user unixuser) {
			// open ~/.ssh/authorized_keys
			file, err := os.Open(path.Join(user.home, ".ssh", "authorized_keys"))
			if err != nil {
				c <- result{ok: false}
				return
			}
			defer file.Close()

			var reader io.Reader = file
			userkeys, err := parseAuthorizedKeys(&reader)
			if err != nil {
				c <- result{ok: false}
				return
			}
			c <- result{
				user: user.name,
				keys: userkeys,
				ok:   true,
			}
		}(user)
	}

	keys := make(map[string][]publickey)

	for _ = range users {
		res := <-c
		if res.ok {
			keys[res.user] = res.keys
		}
	}

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

func parseAllLogFiles() (map[string]map[string]accessSummary, error) {
	allfiles, err := filepath.Glob("/var/log/auth.log*")
	if err != nil {
		return nil, err
	}

	type result struct {
		logs map[string]map[string]accessSummary
		err  error
	}

	c := make(chan result)

	for _, file := range allfiles {
		go func(file string) {
			logs, err := parseLogFile(file)
			if err != nil {
				c <- result{err: err}
				return
			}
			c <- result{logs: logs}
		}(file)
	}

	allLogs := make(map[string]map[string]accessSummary)
	var lastError error

	for _ = range allfiles {
		res := <-c
		if res.err != nil {
			lastError = res.err
		} else {
			mergeLogs(allLogs, res.logs)
		}
	}

	if lastError != nil {
		return nil, lastError
	}
	return allLogs, nil
}

func mergeLogs(target map[string]map[string]accessSummary, source map[string]map[string]accessSummary) {
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
