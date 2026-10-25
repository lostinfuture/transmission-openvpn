package provider

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// BundledRoot is the baked snapshot. Provider directories sit here, not under a contrib/ subdirectory,
	// because the snapshot's CA lines use /etc/openvpn/<provider>/...
	BundledRoot = "/etc/openvpn"
	// FetchRoot is the github tarball extract. It must match openvpn.FetchedRoot.
	FetchRoot   = "/run/openvpn/fetched"
	DefaultRepo = "haugene/vpn-configs-contrib"
	// MaxTarball is the compressed size cap for a github fetch.
	MaxTarball int64 = 32 << 20

	choiceSample = 24
)

// ValidName returns a single lowercase path element.
func ValidName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) || name != filepath.Base(name) {
		return "", fmt.Errorf("invalid OPENVPN_PROVIDER %q", name)
	}
	return name, nil
}

// CryptoPick chooses an index in [0, n).
func CryptoPick(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("no configs to choose")
	}
	if n == 1 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n)), nil
}

// Resolve selects one config file for a baked or fetched provider.
// An empty config uses default.ovpn at the provider root, else the only nested default.ovpn.
// A comma-separated list is a random choice. Names may be a relative path or a unique basename.
// A one-line default.ovpn that names a sibling file is followed.
func Resolve(root, providerName, config string, pick func(int) (int, error)) (string, error) {
	name, err := ValidName(providerName)
	if err != nil {
		return "", err
	}
	if name == "custom" {
		return "", fmt.Errorf("OPENVPN_PROVIDER=custom is a bind mount")
	}
	dir := filepath.Join(root, name)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		have, _ := listProviderNames(root)
		return "", fmt.Errorf("OPENVPN_PROVIDER=%q is not in this snapshot: %s", name, formatChoices(have))
	}
	if pick == nil {
		pick = CryptoPick
	}
	raw := strings.TrimSpace(config)
	if raw == "" {
		p, err := findDefault(dir)
		if err != nil {
			return "", err
		}
		return followPointer(p)
	}
	var paths []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", fmt.Errorf("empty OPENVPN_CONFIG entry")
		}
		p, err := resolveOne(dir, part)
		if err != nil {
			return "", err
		}
		paths = append(paths, p)
	}
	i, err := pick(len(paths))
	if err != nil {
		return "", err
	}
	if i < 0 || i >= len(paths) {
		return "", fmt.Errorf("config pick %d is outside 0..%d", i, len(paths)-1)
	}
	return followPointer(paths[i])
}

// List returns "provider relative/name" lines, without the custom provider.
func List(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "custom" || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rels, err := walkConfigs(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, rel := range rels {
			lines = append(lines, e.Name()+" "+filepath.ToSlash(displayRel(rel)))
		}
	}
	sort.Strings(lines)
	return lines, nil
}

// WriteList prints custom, then one line per baked config. A missing root prints custom and succeeds.
func WriteList(w io.Writer, root string) error {
	if _, err := fmt.Fprintln(w, "custom"); err != nil {
		return err
	}
	lines, err := List(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ln := range lines {
		if _, err := fmt.Fprintln(w, ln); err != nil {
			return err
		}
	}
	return nil
}

func listProviderNames(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "custom" && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func findDefault(dir string) (string, error) {
	rootDef := filepath.Join(dir, "default.ovpn")
	if st, err := os.Lstat(rootDef); err == nil && st.Mode().IsRegular() {
		return rootDef, nil
	}
	rels, err := walkConfigs(dir)
	if err != nil {
		return "", err
	}
	var defs []string
	var shown []string
	for _, rel := range rels {
		shown = append(shown, displayRel(rel))
		if filepath.Base(rel) == "default.ovpn" {
			defs = append(defs, rel)
		}
	}
	switch len(defs) {
	case 1:
		return filepath.Join(dir, filepath.FromSlash(defs[0])), nil
	case 0:
		return "", fmt.Errorf("OPENVPN_CONFIG is unset and %s has no default.ovpn; choices: %s", filepath.Base(dir), formatChoices(shown))
	default:
		return "", fmt.Errorf("multiple default.ovpn files under %s: %s", filepath.Base(dir), formatChoices(defs))
	}
}

func resolveOne(dir, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty OPENVPN_CONFIG entry")
	}
	if filepath.IsAbs(name) || strings.Contains(name, `\`) || strings.Contains(name, "\x00") {
		return "", fmt.Errorf("invalid OPENVPN_CONFIG %q", name)
	}
	for _, p := range strings.Split(name, "/") {
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("invalid OPENVPN_CONFIG %q", name)
		}
	}
	for _, c := range candidateRels(name) {
		p := filepath.Join(dir, filepath.FromSlash(c))
		if !under(dir, p) {
			continue
		}
		st, err := os.Lstat(p)
		if err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	rels, err := walkConfigs(dir)
	if err != nil {
		return "", err
	}
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("OPENVPN_CONFIG %q not found; choices: %s", name, formatChoices(displayAll(rels)))
	}
	want := displayRel(filepath.Base(name))
	var matches []string
	for _, rel := range rels {
		base := filepath.Base(rel)
		if displayRel(base) == want || base == filepath.Base(name) {
			matches = append(matches, rel)
		}
	}
	switch len(matches) {
	case 1:
		return filepath.Join(dir, filepath.FromSlash(matches[0])), nil
	case 0:
		return "", fmt.Errorf("OPENVPN_CONFIG %q not found; choices: %s", name, formatChoices(displayAll(rels)))
	default:
		return "", fmt.Errorf("OPENVPN_CONFIG %q matches more than one file: %s", name, formatChoices(displayAll(matches)))
	}
}

func displayAll(rels []string) []string {
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		out = append(out, displayRel(rel))
	}
	return out
}

func candidateRels(name string) []string {
	low := strings.ToLower(name)
	if strings.HasSuffix(low, ".ovpn") || strings.HasSuffix(low, ".conf") || strings.HasSuffix(low, ".openvpn") {
		return []string{name}
	}
	return []string{name + ".ovpn", name + ".conf", name + ".openvpn", name}
}

func displayRel(rel string) string {
	low := strings.ToLower(rel)
	for _, ext := range []string{".openvpn", ".ovpn", ".conf"} {
		if strings.HasSuffix(low, ext) {
			return rel[:len(rel)-len(ext)]
		}
	}
	return rel
}

func isConfigName(name string) bool {
	base := filepath.Base(name)
	low := strings.ToLower(base)
	if strings.HasSuffix(low, ".ovpn") || strings.HasSuffix(low, ".conf") || strings.HasSuffix(low, ".openvpn") {
		return true
	}
	return base != "" && !strings.Contains(base, ".")
}

func walkConfigs(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() || !isConfigName(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "..") {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// A few contrib default.ovpn files are a single filename, not an OpenVPN config.
func followPointer(path string) (string, error) {
	cur := path
	for hop := 0; hop < 2; hop++ {
		st, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if !st.Mode().IsRegular() || st.Size() > 256 {
			return cur, nil
		}
		b, err := os.ReadFile(cur)
		if err != nil {
			return "", err
		}
		text := strings.TrimSpace(string(b))
		if text == "" || strings.ContainsAny(text, "\n\r \t/\\") || strings.Contains(text, "..") || pointerWords[text] {
			return cur, nil
		}
		dir := filepath.Dir(cur)
		next := ""
		for _, c := range candidateRels(text) {
			p := filepath.Join(dir, c)
			st, err := os.Lstat(p)
			if err == nil && st.Mode().IsRegular() && p != cur {
				next = p
				break
			}
		}
		if next == "" {
			return cur, nil
		}
		cur = next
	}
	return cur, nil
}

var pointerWords = map[string]bool{
	"client": true, "dev": true, "remote": true, "proto": true, "nobind": true, "persist-tun": true, "pull": true,
}

func formatChoices(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	if len(sorted) <= choiceSample {
		return strings.Join(sorted, ", ")
	}
	return fmt.Sprintf("%s … (%d; run ovpn-supervisor list-providers)", strings.Join(sorted[:choiceSample], ", "), len(sorted))
}

func under(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}
