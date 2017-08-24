package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type algorithm struct {
	name   string
	keylen int
}

type publickey struct {
	alg         algorithm
	fingerprint string
	name        string
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
	user        string
	name        string
	alg         algorithm
	lastUse     time.Time
	count       int
	fingerprint string
}

var logPattern = regexp.MustCompile("^([A-Za-z]+ [ 0-9][0-9] [0-9]+:[0-9]+:[0-9]+) [^ ]* sshd\\[[0-9]+\\]: " +
	"Accepted publickey for (.+) from ([0-9a-f.:]+) port [0-9]+ ssh2: [A-Z0-9\\-]+ ([0-9a-f:]+)$")

func main() {
	csv := flag.Bool("csv", false, "Print table as CSV (RFC 4180) using RFC 3339 for dates")
	flag.Parse()

	table, err := buildKeyTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *csv {
		printCSV(table)
	} else {
		printAlignedTable(table)
	}
}

func printAlignedTable(table []tableRow) {
	now := time.Now()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "USER\tNAME\tTYPE\tUSAGE\tCOUNT\tFINGERPRINT\n")

	for _, row := range table {
		var algStr, lastUseStr, countStr string
		if row.count > 0 {
			lastUseStr = durationAsString(now.Sub(row.lastUse))
			countStr = fmt.Sprintf("%5d", row.count)
		} else {
			lastUseStr = "never"
			countStr = "    -"
		}
		if row.alg.name == "RSA" || row.alg.name == "ECDSA" {
			// RSA and ECDSA can be generated with different key lengths
			algStr = fmt.Sprintf("%s-%d", row.alg.name, row.alg.keylen)
		} else {
			// DSA and ED25519 have fixed key lengths
			algStr = row.alg.name
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", row.user, row.name,
			algStr, lastUseStr, countStr, row.fingerprint)
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
		"fingerprint",
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
			row.fingerprint,
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
			summary := logs[user][key.fingerprint]

			table = append(table, tableRow{
				user:        user,
				name:        key.name,
				alg:         key.alg,
				lastUse:     summary.lastUse,
				count:       summary.count,
				fingerprint: key.fingerprint,
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
			alg:         parseKeyType(splits[1]),
			fingerprint: computeFingerprint(splits[1]),
			name:        splits[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func computeFingerprint(pubkey string) string {
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
func parseLogFile(path string, accesses map[string]map[string]accessSummary) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	logFileYear := info.ModTime().Year()
	logFileTimezone := info.ModTime().Location()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gr, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gr.Close()

		scanner = bufio.NewScanner(gr)
	} else {
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		line := scanner.Text()
		log, ok := parseLogLine(logFileYear, logFileTimezone, line)
		if !ok {
			continue
		}

		// create map of fingerprints if not yet there
		if accesses[log.user] == nil {
			accesses[log.user] = make(map[string]accessSummary)
		}

		access := accesses[log.user][log.fingerprint]
		if access.lastUse.IsZero() || log.ts.After(access.lastUse) {
			access.lastUse = log.ts
			access.lastIP = log.ip
		}
		access.count++
		accesses[log.user][log.fingerprint] = access
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
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
	keys := make(map[string][]publickey)

	users, err := getAllUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		// open ~/.ssh/authorized_keys
		file, err := os.Open(path.Join(user.home, ".ssh", "authorized_keys"))
		if err != nil {
			continue
		}
		defer file.Close()

		var reader io.Reader = file
		userkeys, err := parseAuthorizedKeys(&reader)
		if err != nil {
			continue
		}
		keys[user.name] = userkeys
	}

	return keys, nil
}

func durationAsString(dur time.Duration) string {
	var count int
	var unit string

	if dur.Minutes() < 1 {
		return "just now"
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

// Returns a list of all files matching /var/log/auth.log*
func getLogFiles() ([]string, error) {
	const logDir = "/var/log"
	files, err := ioutil.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	logFiles := []string{}
	for _, f := range files {
		if matched, err := filepath.Match("auth.log*", f.Name()); err == nil && matched {
			logFiles = append(logFiles, filepath.Join(logDir, f.Name()))
		}
	}

	return logFiles, nil
}

func parseAllLogFiles() (map[string]map[string]accessSummary, error) {
	allfiles, err := getLogFiles()
	if err != nil {
		return nil, err
	}

	logs := make(map[string]map[string]accessSummary)
	for _, file := range allfiles {
		err := parseLogFile(file, logs)
		if err != nil {
			return nil, err
		}
	}

	return logs, nil
}
