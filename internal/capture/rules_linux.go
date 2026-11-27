package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"proxy.local/m0/internal/config"
)

type tools struct{ ip, nft string }

func ownedTools() (tools, error) {
	find := func(name string) string {
		for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			path := filepath.Join(directory, name)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				return path
			}
		}
		return ""
	}
	t := tools{find("ip"), find("nft")}
	if t.ip == "" || t.nft == "" {
		return tools{}, errors.New("capture requires ip and nft")
	}
	return t, nil
}

type journal struct {
	Namespace    string
	HostAllowed  bool
	Table        string
	RulePriority string `json:",omitempty"`
	IPv4         bool
	IPv6         bool
}

func (j journal) priority() string {
	if j.RulePriority != "" {
		return j.RulePriority
	}
	return rulePriority
}

const journalName = "capture.json"
const routeProtocol = "99"
const localRouteType = "2" // RTN_LOCAL in ip -N JSON output.
const localRouteTable = "255"

func parseRulePriority(raw any) (int, bool) {
	switch v := raw.(type) {
	case float64:
		n := int(v)
		if float64(n) != v || n < 0 {
			return 0, false
		}
		return n, true
	case int:
		if v < 0 {
			return 0, false
		}
		return v, true
	case string:
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func validRulePriority(value string) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n > 0
}

func isLocalPolicyRule(rule map[string]any) bool {
	table := fmt.Sprint(rule["table"])
	return table == "local" || table == localRouteTable
}

func selectRulePriority(ruleSets ...[]map[string]any) (string, error) {
	defaultPriority, err := strconv.Atoi(rulePriority)
	if err != nil {
		return "", err
	}
	used := map[int]bool{}
	maxLocal := 0
	minNonLocal := -1

	for _, rules := range ruleSets {
		for _, rule := range rules {
			if fmt.Sprint(rule["table"]) == routeTable || rule["fwmark"] != nil {
				return "", errors.New("policy routing conflicts with the M1 gateway capture")
			}
			priority, ok := parseRulePriority(rule["priority"])
			if !ok {
				return "", fmt.Errorf("invalid policy rule priority %v", rule["priority"])
			}
			used[priority] = true
			if isLocalPolicyRule(rule) {
				if priority > maxLocal {
					maxLocal = priority
				}
				continue
			}
			if minNonLocal == -1 || priority < minNonLocal {
				minNonLocal = priority
			}
		}
	}

	candidate := defaultPriority
	if minNonLocal != -1 && minNonLocal <= candidate {
		candidate = minNonLocal - 1
	}
	for candidate > maxLocal && used[candidate] {
		candidate--
	}
	if candidate <= maxLocal || candidate < 1 {
		return "", errors.New("policy routing conflicts with capture: no available rule priority before existing routing rules")
	}
	return strconv.Itoa(candidate), nil
}

func captureLock(namespace string) (*os.File, error) {
	identifier := strings.TrimSuffix(strings.TrimPrefix(namespace, "net:["), "]")
	directory := os.Getenv("PROXY_CAPTURE_LOCK_DIR")
	if directory == "" {
		directory = "/run"
	}
	lock, err := os.OpenFile(filepath.Join(directory, "proxy-capture-"+identifier+".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another capture transaction is active: %w", err)
	}
	return lock, nil
}

func command(binary, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(input)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(binary), strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func (t tools) list(family, object string, selector ...string) ([]map[string]any, error) {
	args := []string{"-j", "-N", family, object, "show"}
	if object == "route" {
		args = append(args, "table", "all")
	}
	data, err := command(t.ip, "", append(args, selector...)...)
	if err != nil {
		return nil, err
	}
	var entries []map[string]any
	err = json.Unmarshal(data, &entries)
	return entries, err
}

func (t tools) prepare(cfg config.Capture, directory string, upstreams ...[]upstreamGroup) (journal, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return journal{}, err
	}
	state := journal{Namespace: cfg.Namespace, HostAllowed: cfg.Scope == "global", Table: "proxy_m1_" + hex.EncodeToString(id)}
	{
		state.IPv4, state.IPv6 = cfg.IPv4, cfg.IPv6
		var ruleSets [][]map[string]any
		for _, family := range enabledFamilies(cfg) {
			rules, err := t.list(family, "rule")
			if err != nil {
				return journal{}, err
			}
			ruleSets = append(ruleSets, rules)
			routes, err := t.list(family, "route")
			if err != nil {
				return journal{}, err
			}
			for _, route := range routes {
				if fmt.Sprint(route["table"]) == routeTable {
					return journal{}, errors.New("M1 policy route table is occupied")
				}
			}
		}
		priority, err := selectRulePriority(ruleSets...)
		if err != nil {
			return journal{}, err
		}
		state.RulePriority = priority
	}
	if _, err := command(t.nft, nftRules(state.Table, cfg, upstreams...), "-c", "-f", "-"); err != nil {
		return journal{}, err
	}

	file, err := os.OpenFile(filepath.Join(directory, journalName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return journal{}, fmt.Errorf("create capture journal: %w", err)
	}
	err = errors.Join(json.NewEncoder(file).Encode(state), file.Sync(), file.Close())
	if err != nil {
		return journal{}, errors.Join(err, os.Remove(filepath.Join(directory, journalName)))
	}
	return state, nil
}

func routeArgs(family, verb string) []string {
	address := "0.0.0.0/0"
	if family == "-6" {
		address = "::/0"
	}
	return []string{family, "route", verb, "local", address, "dev", "lo", "table", routeTable, "proto", routeProtocol}
}
func ruleArgs(family, verb, priority string) []string {
	return []string{family, "rule", verb, "priority", priority, "fwmark", captureMark + "/" + mask, "lookup", routeTable}
}

func (t tools) activate(state journal, cfg config.Capture, upstreams ...[]upstreamGroup) error {
	priority := state.priority()
	for _, family := range enabledFamilies(config.Capture{IPv4: state.IPv4, IPv6: state.IPv6}) {
		if _, err := command(t.ip, "", routeArgs(family, "add")...); err != nil {
			return err
		}
		if _, err := command(t.ip, "", ruleArgs(family, "add", priority)...); err != nil {
			return err
		}
	}
	_, err := command(t.nft, nftRules(state.Table, cfg, upstreams...), "-f", "-")
	return err
}

func (t tools) cleanup(state journal, directory string) error {
	if err := checkNamespace(state.Namespace, state.HostAllowed); err != nil {
		return err
	}
	data, err := command(t.nft, "", "-j", "list", "tables")
	if err != nil {
		return err
	}
	var nft struct {
		Nftables []struct{ Table struct{ Family, Name string } }
	}
	if err := json.Unmarshal(data, &nft); err != nil {
		return err
	}
	for _, item := range nft.Nftables {
		if item.Table.Family == "inet" && item.Table.Name == state.Table {
			if _, err := command(t.nft, "", "delete", "table", "inet", state.Table); err != nil {
				return err
			}
			break
		}
	}

	var cleanupErr error
	priority := state.priority()
	for _, family := range enabledFamilies(config.Capture{IPv4: state.IPv4, IPv6: state.IPv6}) {
		rules, err := t.list(family, "rule")
		cleanupErr = errors.Join(cleanupErr, err)
		for _, rule := range rules {
			if fmt.Sprint(rule["priority"]) == priority && fmt.Sprint(rule["table"]) == routeTable &&
				rule["fwmark"] == captureMark && rule["fwmask"] == mask {
				_, err := command(t.ip, "", ruleArgs(family, "del", priority)...)
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
		routes, err := t.list(family, "route", "proto", routeProtocol)
		cleanupErr = errors.Join(cleanupErr, err)
		for _, route := range routes {
			kind := fmt.Sprint(route["type"])
			if fmt.Sprint(route["table"]) == routeTable && (kind == localRouteType || kind == "local") && route["dst"] == "default" &&
				route["dev"] == "lo" {
				_, err := command(t.ip, "", routeArgs(family, "del")...)
				cleanupErr = errors.Join(cleanupErr, err)
			}
		}
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	return os.Remove(filepath.Join(directory, journalName))
}

var tableName = regexp.MustCompile(`^proxy_m1_[0-9a-f]{24}$`)

func Cleanup(directory string) error {
	data, err := os.ReadFile(filepath.Join(directory, journalName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state journal
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if !tableName.MatchString(state.Table) {
		return errors.New("invalid owned table name")
	}
	if state.RulePriority != "" && !validRulePriority(state.RulePriority) {
		return errors.New("invalid owned rule priority")
	}
	if err := checkNamespace(state.Namespace, state.HostAllowed); err != nil {
		return err
	}
	lock, err := captureLock(state.Namespace)
	if err != nil {
		return err
	}
	defer lock.Close()
	// A guard may have removed or replaced the journal before we took its lock.
	current, err := os.ReadFile(filepath.Join(directory, journalName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(current) != string(data) {
		return errors.New("capture journal changed during cleanup")
	}
	t, err := ownedTools()
	if err != nil {
		return err
	}
	return t.cleanup(state, directory)
}
