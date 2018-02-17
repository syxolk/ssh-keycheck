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
	"encoding/json"
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

type exitCode int

const (
	success exitCode = iota
	failedToRun
	invalidFlags
)

type algorithmType int

const (
	unknownAlgorithm algorithmType = iota
	rsa
	dsa
	ecdsa
	ed25519
)

var algorithmNames = [...]string{
	"[unknown]",
	"RSA",
	"DSA",
	"ECDSA",
	"ED25519",
}

type algorithm struct {
	name   algorithmType
	keylen int
}

type publickey struct {
	alg               algorithm
	fingerprintMD5    string
	fingerprintSHA256 string
	comment           string
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
	comment           string
	alg               algorithm
	lastUse           time.Time
	count             int
	fingerprintMD5    string
	fingerprintSHA256 string
	lastIP            net.IP
}

type filterOptions struct {
	now          time.Time
	onlyInsecure bool
	onlySecure   bool
	unusedDays   int
	usedDays     int
	user         *regexp.Regexp
}

var logPattern = regexp.MustCompile("^([A-Za-z]+ [ 0-9][0-9] [0-9]+:[0-9]+:[0-9]+) [^ ]* sshd\\[[0-9]+\\]: " +
	"Accepted publickey for (.+) from ([0-9a-f.:]+) port [0-9]+ ssh2: [A-Z0-9\\-]+ ([0-9a-f:]+)$")

func main() {
	os.Exit(int(mainHelper(os.Args, "/", os.Stdout, os.Stderr)))
}

func mainHelper(args []string, prefix string, stdout io.Writer, stderr io.Writer) exitCode {
	var csv, json, printMD5, printSHA256, showVersion, showHelp bool
	var userRegexp string
	fopts := filterOptions{now: time.Now()}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&csv, "csv", false, "Print table as CSV (RFC 4180) using RFC 3339 for dates")
	flags.BoolVar(&json, "json", false, "Print table as JSON using RFC 3339 for dates")
	flags.BoolVar(&printMD5, "fingerprint-md5", false, "Show fingerprint (MD5) column")
	flags.BoolVar(&printSHA256, "fingerprint-sha256", false, "Show fingerprint (SHA256) column")
	flags.BoolVar(&showVersion, "version", false, "Show version and exit")
	flags.BoolVar(&showHelp, "help", false, "Show help and exit")
	flags.BoolVar(&fopts.onlySecure, "secure", false, "List only secure keys")
	flags.BoolVar(&fopts.onlyInsecure, "insecure", false, "List only insecure keys")
	flags.IntVar(&fopts.usedDays, "used", 0, "List only keys used in the last x days")
	flags.IntVar(&fopts.unusedDays, "unused", 0, "List only keys more than x days not used")
	flags.StringVar(&userRegexp, "user", "", "List only keys with matching user name")
	err := flags.Parse(args[1:])

	if err != nil {
		return invalidFlags
	}

	if userRegexp != "" {
		fopts.user, err = regexp.Compile(userRegexp)
		if err != nil {
			fmt.Fprintf(stderr, "Error for flag -user: %s\n", err)
			return invalidFlags
		}
	}

	err = fopts.validate()
	if err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		return invalidFlags
	}

	if showVersion {
		fmt.Fprintln(stderr, "ssh-keycheck", version, runtime.Version(),
			runtime.GOOS, runtime.GOARCH)
		return success
	}

	if showHelp {
		fmt.Fprintf(stderr, "Usage of %s:\n", args[0])
		flags.PrintDefaults()
		return success
	}

	if json && csv {
		fmt.Fprintln(stderr, "Cannot use -csv and -json together")
		return invalidFlags
	}

	table, err := buildKeyTable(prefix)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return failedToRun
	}

	table = filterKeyTable(table, &fopts)

	if json {
		printJSON(stdout, table)
	} else if csv {
		printCSV(stdout, table)
	} else {
		printAlignedTable(stdout, table, printMD5, printSHA256, fopts.now)
	}
	return success
}

func printAlignedTable(out io.Writer, table []tableRow, printMD5, printSHA256 bool, now time.Time) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "USER\tCOMMENT\tTYPE\tSECURITY\tLAST USE\tCOUNT\tLAST IP")
	if printMD5 {
		fmt.Fprintf(w, "\tFINGERPRINT-MD5")
	}
	if printSHA256 {
		fmt.Fprintf(w, "\tFINGERPRINT-SHA256")
	}
	fmt.Fprintln(w)

	for _, row := range table {
		var lastUseStr, lastIPStr, countStr, insecureStr string
		if row.count > 0 {
			lastUseStr = durationPhrase(now.Sub(row.lastUse))
			countStr = fmt.Sprintf("%5d", row.count)
			lastIPStr = row.lastIP.String()
		} else {
			lastUseStr = "never"
			countStr = "    -"
			lastIPStr = "-"
		}
		if row.alg.isSecure() {
			insecureStr = "ok"
		} else {
			insecureStr = "insecure"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s", row.user, row.comment,
			row.alg.String(), insecureStr, lastUseStr, countStr, lastIPStr)
		if printMD5 {
			fmt.Fprintf(w, "\t%s", row.fingerprintMD5)
		}
		if printSHA256 {
			fmt.Fprintf(w, "\t%s", row.fingerprintSHA256)
		}
		fmt.Fprintln(w)
	}

	w.Flush()
}

func (r *tableRow) MarshalJSON() ([]byte, error) {
	j := struct {
		User              string     `json:"user"`
		Comment           string     `json:"comment"`
		Type              string     `json:"type"`
		Keylen            int        `json:"keylen"`
		Secure            bool       `json:"secure"`
		LastUse           *time.Time `json:"last_use"`
		Count             int        `json:"count"`
		LastIP            *net.IP    `json:"last_ip"`
		FingerprintMD5    string     `json:"fingerprint_md5"`
		FingerprintSHA256 string     `json:"fingerprint_sha256"`
	}{
		User:              r.user,
		Comment:           r.comment,
		Type:              r.alg.name.String(),
		Keylen:            r.alg.keylen,
		Secure:            r.alg.isSecure(),
		Count:             r.count,
		FingerprintMD5:    r.fingerprintMD5,
		FingerprintSHA256: r.fingerprintSHA256,
	}
	if r.count > 0 {
		// This is a trick to output null for last_use and last_ip if
		// count == 0 instead of zero time and empty string
		j.LastUse = &r.lastUse
		j.LastIP = &r.lastIP
	}

	return json.Marshal(j)
}

func printJSON(out io.Writer, table []tableRow) error {
	m := json.NewEncoder(out)
	return m.Encode(table)
}

func printCSV(out io.Writer, table []tableRow) {
	w := csv.NewWriter(out)
	w.Write([]string{
		"user",
		"comment",
		"type",
		"keylen",
		"secure",
		"last_use",
		"count",
		"last_ip",
		"fingerprint_md5",
		"fingerprint_sha256",
	})

	for _, row := range table {
		lastUseStr := ""
		lastIPStr := ""
		if row.count > 0 {
			// if the key was never used, the timestamp should not be printed
			lastUseStr = row.lastUse.Format(time.RFC3339)
			lastIPStr = row.lastIP.String()
		}
		w.Write([]string{
			row.user,
			row.comment,
			row.alg.name.String(),
			strconv.Itoa(row.alg.keylen),
			strconv.FormatBool(row.alg.isSecure()),
			lastUseStr,
			strconv.Itoa(row.count),
			lastIPStr,
			row.fingerprintMD5,
			row.fingerprintSHA256,
		})
	}

	w.Flush()
}

// Get all logs and authorized keys and combine them to a single table structure.
// This function queries authorized keys and logs in parallel.
func buildKeyTable(prefix string) ([]tableRow, error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var allKeys map[string][]publickey
	var allLogs logSummary
	var allKeysErr, allLogsErr error

	// Execute log file parsing and collecting authorized keys in parallel
	go func() {
		allKeys, allKeysErr = getAuthorizedKeysForAllUsers(prefix)
		wg.Done()
	}()
	go func() {
		allLogs, allLogsErr = parseAllLogFiles(prefix)
		wg.Done()
	}()

	// Wait for both goroutines to finish
	wg.Wait()

	// Check for any errors that occurred
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
				comment:           key.comment,
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
func parseAuthorizedKeys(file io.Reader) ([]publickey, error) {
	// Every public key is in its own line
	var keys []publickey
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Lines starting with '#' and empty lines are ignored as comments.
		// http://man.he.net/man5/authorized_keys
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		splits := strings.SplitN(line, " ", 3)
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
			comment:           splits[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Error while scanning authorized keys: %s", err)
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
// Returns "", nil if any parsing error occurred
func splitPubkey(pubkey []byte) (string, []int) {
	buf := bytes.NewReader(pubkey)
	firstPart := ""
	var partLengths []int
	for {
		var length int32
		if err := binary.Read(buf, binary.BigEndian, &length); err == io.EOF {
			// Did not read any byte because the last read reached the end already
			// This is the only valid exit from the loop
			break
		}

		if length <= 0 || length > 4096 {
			// Stop parsing if any part has a negative length
			// or is bigger than 4 KB.
			// The longest possible part is 2049 bytes (for RSA-16384) anyway.
			return "", nil
		} else if len(partLengths) == 0 {
			// Convert the first part to a string
			data := make([]byte, length)
			if n, _ := buf.Read(data); int32(n) != length {
				// Stop parsing if not enough bytes were available
				return "", nil
			}
			firstPart = string(data)
		} else if off, err := buf.Seek(int64(length), io.SeekCurrent); err != nil || int(off) > len(pubkey) {
			// Stop parsing if skipping bytes was not possible
			return "", nil
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
		return nil, fmt.Errorf("Error while checking mod time for file: %s", err)
	}
	logFileYear := info.ModTime().Year()
	logFileTimezone := info.ModTime().Location()

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error while opening logs: %s", err)
	}
	defer file.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gr, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("Error while unzipping logs: %s", err)
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
		return nil, fmt.Errorf("Error while scanning logs: %s", err)
	}

	return logs, nil
}

// Parse a line from an /var/log/auth.log* file and returns either an
// access object and true if successfully parsed or an empty object and false
// if the line could not be parsed.
// Since sshd does not log the year or timezone it must be given by parameter
// in order to parse the timestamp.
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
		return nil, fmt.Errorf("Error while parsing users: %s", err)
	}

	return users, nil
}

// Wrapper around parseAllUsers that reads from /etc/passwd
func getAllUsers(prefix string) ([]unixuser, error) {
	file, err := os.Open(path.Join(prefix, "etc", "passwd"))
	if err != nil {
		return nil, fmt.Errorf("Error while getting all users: %s", err)
	}
	defer file.Close()

	return parseAllUsers(file)
}

// Opens ~/.ssh/authorized_keys for all users and returns
// every key parsed into algorithm, key and name in a map.
// This function is parallelized on all authorized_keys files.
func getAuthorizedKeysForAllUsers(prefix string) (map[string][]publickey, error) {
	users, err := getAllUsers(prefix)
	if err != nil {
		return nil, fmt.Errorf("Error while collecting authorized keys for all users: %s", err)
	}

	keys := make(map[string][]publickey)
	var mut sync.Mutex
	var wg sync.WaitGroup

	for _, user := range users {
		wg.Add(1)
		go func(user unixuser) {
			defer wg.Done()

			// open ~/.ssh/authorized_keys
			file, err := os.Open(path.Join(prefix, user.home, ".ssh", "authorized_keys"))
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

// Format a duration as human-readable text relative to now in past tense.
// Returns "just now" if the duration is below one second.
// Returns "x second(s) ago" if the duration is below a minute.
// Returns "x minute(s) ago" if the duration is below an hour.
// Returns "x hour(s) ago" if the duration is below one day.
// Otherwise returns "x day(s) ago".
func durationPhrase(dur time.Duration) string {
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

// Gets all files named /var/log/auth.log*, calls parseLogFile on each file
// and merges the results with mergeLogs.
// This function is parallelized on all auth.log* files.
func parseAllLogFiles(prefix string) (logSummary, error) {
	allfiles, err := filepath.Glob(path.Join(prefix, "var", "log", "auth.log*"))
	if err != nil {
		return nil, fmt.Errorf("Error while collecting auth.log files: %s", err)
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

// Takes two logSummary structures and merges everything from source into target.
// For the same user and fingerprint, the counts are summed up and the last
// use and last ip are overwritten in target if the last use in source
// happened later.
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

// Checks if the algorithm is safe to be used
// DSA: https://www.gentoo.org/support/news-items/2015-08-13-openssh-weak-keys.html
// RSA: https://www.keylength.com/en/4/
// ECDSA: https://wiki.archlinux.org/index.php/SSH_keys#ECDSA
func (alg *algorithm) isSecure() bool {
	return (alg.name == rsa && alg.keylen >= 2048) || alg.name == ed25519
}

// Return a string representation of the given algorithm.
// Returns the name and key length for RSA and ECDSA.
// Returns only the name for DSA and ED25519.
func (alg *algorithm) String() string {
	if alg.name == dsa || alg.name == ed25519 {
		// DSA and ED25519 have fixed key lengths
		return alg.name.String()
	}

	// RSA and ECDSA can be generated with different key lengths
	return fmt.Sprintf("%s-%d", alg.name, alg.keylen)
}

// Return a string representation of the given algorithm type.
func (t algorithmType) String() string {
	return algorithmNames[t]
}

// Check if the filter options don't specify contradictory filter criteria.
// Returns nil if no problems were found and the filter options are valid.
// Returns an error if there were any conflicts.
func (opt *filterOptions) validate() error {
	if opt.onlySecure && opt.onlyInsecure {
		return fmt.Errorf("Cannot use -secure and -insecure together")
	}
	if opt.usedDays < 0 {
		return fmt.Errorf("Flag -used cannot be set to a negative number: %d",
			opt.usedDays)
	}
	if opt.unusedDays < 0 {
		return fmt.Errorf("Flag -unused cannot be set to a negative number: %d",
			opt.unusedDays)
	}
	if opt.usedDays > 0 && opt.unusedDays > 0 && opt.unusedDays >= opt.usedDays {
		return fmt.Errorf("Flag -unused cannot be equal or larger than -used: %d >= %d",
			opt.unusedDays, opt.usedDays)
	}

	return nil
}

// Filters a given key table by certain filter criteria.
// Returns the rows matching the criteria, in the same order as in the input table.
func filterKeyTable(table []tableRow, opt *filterOptions) (ret []tableRow) {
	usedDays := 24 * time.Hour * time.Duration(opt.usedDays)
	unusedDays := 24 * time.Hour * time.Duration(opt.unusedDays)

	for _, r := range table {
		sinceLastUse := opt.now.Sub(r.lastUse)
		if opt.onlySecure && !r.alg.isSecure() {
			continue
		}
		if opt.onlyInsecure && r.alg.isSecure() {
			continue
		}
		if opt.usedDays > 0 && (r.count == 0 || sinceLastUse > usedDays) {
			continue
		}
		if opt.unusedDays > 0 && r.count > 0 && sinceLastUse < unusedDays {
			continue
		}
		if opt.user != nil && opt.user.FindString(r.user) == "" {
			continue
		}

		ret = append(ret, r)
	}
	return
}
