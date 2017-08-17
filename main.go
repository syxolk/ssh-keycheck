package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

type publickey struct {
	algorithm   string
	key         string
	fingerprint string
	name        string
}

type unixuser struct {
	name string
	home string
}

type access struct {
	ts   time.Time
	user string
	ip   string
}

func main() {
	allkeys, err := getAuthorizedKeysForAllUsers()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logs, err := parseAllLogFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	now := time.Now()

	var usernames []string
	for k := range allkeys {
		usernames = append(usernames, k)
	}
	sort.Strings(usernames)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "USER\tNAME\tALG\tUSAGE\tCOUNT\tFINGERPRINT\n")

	for _, user := range usernames {
		for _, key := range allkeys[user] {
			found, lastUse, count := findLog(logs, key.fingerprint, user)

			var lastUseStr string
			if found {
				lastUseStr = durationAsString(now.Sub(lastUse))
			} else {
				lastUseStr = "never"
			}
			var countStr string
			if count > 0 {
				countStr = fmt.Sprintf("%5d", count)
			} else {
				countStr = "    -"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", user, key.name,
				key.algorithm, lastUseStr, countStr, key.fingerprint)
		}
	}

	w.Flush()
}

func getAuthorizedKeys(homedir string) ([]publickey, error) {
	// open ~/.ssh/authorized_keys
	file, err := os.Open(path.Join(homedir, ".ssh", "authorized_keys"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// every public key is in its own line
	var keys []publickey
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		splits := strings.SplitN(scanner.Text(), " ", 3)
		if len(splits) != 3 {
			continue
		}
		keys = append(keys, publickey{
			algorithm:   splits[0],
			key:         splits[1],
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

func parseLogFile(path string, accesses map[string][]access) error {
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

	pattern := regexp.MustCompile("([A-Za-z]+ [ 0-9][0-9] [0-9]+:[0-9]+:[0-9]+) [^ ]* sshd\\[[0-9]+\\]: Accepted publickey for (.+) from ([0-9a-f.:]+) port [0-9]+ ssh2: RSA ([0-9a-f:]+)")

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Accepted publickey for") {
			m := pattern.FindStringSubmatch(line)
			if len(m) != 5 {
				continue
			}
			fingerprint := m[4]
			ts, err := time.ParseInLocation("2006 Jan 2 15:04:05", strconv.Itoa(logFileYear)+" "+m[1], logFileTimezone)
			if err != nil {
				continue
			}
			accesses[fingerprint] = append(accesses[fingerprint],
				access{ts: ts, user: m[2], ip: m[3]})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// Read /etc/passwd and return all users and their corresponding home directory
func getAllUsers() ([]unixuser, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

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

func getAuthorizedKeysForAllUsers() (map[string][]publickey, error) {
	keys := make(map[string][]publickey)

	users, err := getAllUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		userkeys, err := getAuthorizedKeys(user.home)
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

func parseAllLogFiles() (map[string][]access, error) {
	allfiles, err := getLogFiles()
	if err != nil {
		return nil, err
	}

	logs := make(map[string][]access)
	for _, file := range allfiles {
		err := parseLogFile(file, logs)
		if err != nil {
			return nil, err
		}
	}

	return logs, nil
}

// Find the last log entry for (fingerprint, user) in the given logs mapping
// Returns a tuple of (found, lastUse, count)
// lastUse.IsZero() == true iff found == false
func findLog(logs map[string][]access, fingerprint string, user string) (bool, time.Time, int) {
	found := false
	var lastUse time.Time
	count := 0

	for _, log := range logs[fingerprint] {
		if log.user != user {
			continue
		}
		found = true
		count++
		if lastUse.IsZero() || log.ts.After(lastUse) {
			lastUse = log.ts
		}
	}

	return found, lastUse, count
}
