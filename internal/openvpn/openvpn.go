// Package openvpn sanitizes a client config and rewrites remotes to resolved addresses.
package openvpn

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	authPath = "/run/openvpn/auth"
	// OpenVPN 2.7 allows one parameter. The program and its argument are one quoted value.
	hookUp   = `"/usr/bin/ovpn-supervisor hook-up"`
	hookDown = `"/usr/bin/ovpn-supervisor hook-down"`
	// FetchedRoot is where a github config tarball is extracted.
	// Absolute /etc/openvpn paths in those files are rewritten under this prefix.
	FetchedRoot = "/run/openvpn/fetched"
)

// Endpoint is one OUTPUT accept: an address OpenVPN will handshake with.
type Endpoint struct {
	Addr  string
	Proto string
	Port  int
}

// Result is a config OpenVPN is allowed to read.
type Result struct {
	Config    string
	Endpoints []Endpoint
	User      string
	Password  string
	Stripped  []string
}

// Lookup resolves a remote hostname. Addresses that are already literals are not passed here.
type Lookup func(host string) ([]netip.Addr, error)

// Prepare sanitizes srcPath, rejects dangerous OPENVPN_OPTS, and rewrites every remote to IP literals.
// OpenVPN then has nothing to resolve on reconnect. haveCreds reports env or secret-file credentials.
func Prepare(srcPath string, opts []string, haveCreds bool, lookup Lookup, ipv6 bool) (Result, error) {
	return prepare(srcPath, opts, haveCreds, lookup, ipv6, FetchedRoot)
}

func prepare(srcPath string, opts []string, haveCreds bool, lookup Lookup, ipv6 bool, fetchRoot string) (Result, error) {
	if err := rejectOpts(opts); err != nil {
		return Result{}, err
	}
	text, user, pass, stripped, err := load(srcPath, 0, fetchRoot)
	if err != nil {
		return Result{}, err
	}
	// load rewrites a bare auth-user-pass to the auth-file path, so the
	// rewritten text is what shows the directive was present.
	askedAuth := strings.Contains(text, "auth-user-pass ") || user != ""
	if user != "" && haveCreds {
		user, pass = "", ""
	}
	if askedAuth && !haveCreds && user == "" {
		return Result{}, fmt.Errorf("openvpn config requires credentials")
	}
	if haveCreds || user != "" {
		if !strings.Contains(text, "auth-user-pass "+authPath) {
			text = strings.TrimRight(text, "\n") + "\nauth-user-pass " + authPath + "\n"
		}
	}
	if !strings.Contains(text, "\nallow-compression no\n") && !strings.HasPrefix(text, "allow-compression no\n") {
		text = strings.TrimRight(text, "\n") + "\nallow-compression no\n"
	}
	text = strings.TrimRight(text, "\n") + "\n" + strings.Join([]string{
		"script-security 2",
		"route-up " + hookUp,
		"route-pre-down " + hookDown,
		"dns-updown disable",
		"",
	}, "\n")
	rewritten, eps, err := rewriteRemotes(text, lookup, ipv6)
	if err != nil {
		return Result{}, err
	}
	if strings.Count(rewritten, "script-security") != 1 {
		return Result{}, fmt.Errorf("sanitized config has %d script-security lines", strings.Count(rewritten, "script-security"))
	}
	return Result{Config: rewritten, Endpoints: eps, User: user, Password: pass, Stripped: stripped}, nil
}

func load(path string, depth int, fetchRoot string) (string, string, string, []string, error) {
	if depth > 1 {
		return "", "", "", nil, fmt.Errorf("openvpn config include nested too deep")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", nil, err
	}
	items, err := scan(string(raw))
	if err != nil {
		return "", "", "", nil, err
	}
	var b strings.Builder
	var user, pass string
	var stripped []string
	for _, it := range items {
		switch it.kind {
		case kindComment, kindBlank:
			continue
		case kindBlock:
			if it.key == "auth-user-pass" {
				u, p, err := inlineAuth(it.body)
				if err != nil {
					return "", "", "", nil, err
				}
				user, pass = u, p
				stripped = append(stripped, "auth-user-pass")
				continue
			}
			if !allowedBlock(it.key) {
				return "", "", "", nil, fmt.Errorf("openvpn: refused block <%s>", it.key)
			}
			if it.key == "connection" {
				body, extra, err := sanitizeBlock(path, it.body, fetchRoot)
				if err != nil {
					return "", "", "", nil, err
				}
				stripped = append(stripped, extra...)
				fmt.Fprintf(&b, "<connection>\n%s</connection>\n", body)
				continue
			}
			fmt.Fprintf(&b, "<%s>\n%s</%s>\n", it.key, it.body, it.key)
		case kindLine:
			key, args := splitKey(it.raw)
			if key == "config" {
				inc, err := includePath(path, strings.TrimSpace(args))
				if err != nil {
					return "", "", "", nil, err
				}
				nested, u, p, extra, err := load(inc, depth+1, fetchRoot)
				if err != nil {
					return "", "", "", nil, err
				}
				if u != "" {
					user, pass = u, p
				}
				stripped = append(stripped, extra...)
				b.WriteString(nested)
				continue
			}
			if strip, _ := strippedDirective(key); strip {
				stripped = append(stripped, key)
				continue
			}
			if key == "allow-compression" && strings.TrimSpace(args) != "no" {
				stripped = append(stripped, key)
				continue
			}
			if !allowedLine(key) {
				return "", "", "", nil, fmt.Errorf("openvpn: refused unknown directive %q", key)
			}
			if key == "providers" {
				if err := checkProviders(args); err != nil {
					return "", "", "", nil, err
				}
			}
			if key == "auth-user-pass" {
				b.WriteString("auth-user-pass " + authPath + "\n")
				continue
			}
			if pathDirective(key) {
				line, err := rewritePathLine(path, it.raw, fetchRoot)
				if err != nil {
					return "", "", "", nil, err
				}
				b.WriteString(line + "\n")
				continue
			}
			b.WriteString(strings.TrimRight(it.raw, "\r") + "\n")
		}
	}
	return b.String(), user, pass, stripped, nil
}

func strippedDirective(key string) (bool, string) {
	switch key {
	case "up", "down", "route-up", "route-pre-down", "ipchange", "client-connect", "client-disconnect",
		"learn-address", "auth-user-pass-verify", "tls-verify", "plugin", "management", "askpass",
		"daemon", "writepid", "user", "group", "script-security", "dns-updown", "chroot", "cd",
		"log", "log-append", "status", "status-version", "replay-persist", "tmp-dir", "setenv",
		"setenv-safe", "tls-crypt-v2-verify", "client-crresponse", "down-pre", "up-restart",
		"iproute", "route-noexec", "ifconfig-noexec", "comp-lzo", "compress", "comp-noadapt",
		"remote-random-hostname":
		return true, "not passed to openvpn"
	default:
		return false, ""
	}
}

func allowedLine(key string) bool {
	_, ok := allowedLines[key]
	return ok
}

// allowedLines is the client directive allowlist. Stripped directives are absent on purpose.
var allowedLines = map[string]struct{}{
	"allow-compression": {}, "allow-pull-fqdn": {}, "auth": {}, "auth-gen-token": {},
	"auth-nocache": {}, "auth-retry": {}, "auth-token": {}, "auth-user-pass": {},
	"bind": {}, "block-outside-dns": {}, "ca": {}, "cert": {}, "cipher": {}, "client": {},
	"client-nat": {}, "compat-mode": {}, "connect-freq": {}, "connect-retry": {},
	"connect-retry-max": {}, "connect-timeout": {}, "crl-verify": {}, "data-ciphers": {}, "data-ciphers-fallback": {},
	"dev": {}, "dev-type": {}, "dh": {}, "dhcp-option": {}, "disable-dco": {}, "disable-occ": {},
	"ecdh-curve": {}, "enable-occ": {}, "explicit-exit-notify": {}, "fast-io": {}, "float": {},
	"fragment": {}, "hand-window": {}, "http-proxy": {}, "http-proxy-option": {}, "ifconfig": {},
	"ifconfig-ipv6": {}, "ignore-unknown-option": {}, "inactive": {}, "keepalive": {}, "key": {},
	"key-direction": {}, "key-method": {}, "keysize": {}, "link-mtu": {}, "local": {}, "lport": {},
	"machine-readable-output": {}, "mark": {}, "max-routes": {}, "memstats": {}, "mlock": {},
	"mssfix": {}, "mtu-disc": {}, "mtu-test": {}, "mute": {}, "mute-replay-warnings": {},
	"ncp-ciphers": {}, "ncp-disable": {}, "nice": {}, "nobind": {}, "ns-cert-type": {},
	"passtos": {}, "persist-key": {}, "persist-remote-ip": {}, "persist-tun": {}, "ping": {},
	"ping-exit": {}, "ping-restart": {}, "ping-timer-rem": {}, "pkcs12": {}, "port": {}, "proto": {},
	"proto-force": {}, "providers": {}, "pull": {}, "pull-filter": {}, "push-peer-info": {},
	"rcvbuf": {}, "redirect-gateway": {}, "redirect-private": {}, "remap-usr1": {}, "remote": {},
	"remote-cert-eku": {}, "remote-cert-ku": {}, "remote-cert-tls": {}, "remote-random": {},
	"reneg-bytes": {}, "reneg-sec": {}, "replay-window": {}, "resolv-retry": {},
	"route": {}, "route-delay": {}, "route-gateway": {}, "route-ipv6": {}, "route-method": {},
	"route-metric": {}, "route-nopull": {}, "route-up-delay": {}, "rport": {},
	"secret": {}, "server-poll-timeout": {}, "single-session": {}, "sndbuf": {}, "socket-flags": {},
	"socks-proxy": {}, "socks-proxy-retry": {}, "static-challenge": {}, "suppress-timestamps": {},
	"tls-auth": {}, "tls-cert-profile": {}, "tls-cipher": {}, "tls-ciphersuites": {},
	"tls-client": {}, "tls-crypt": {}, "tls-crypt-v2": {}, "tls-exit": {}, "tls-groups": {},
	"tls-version-max": {}, "tls-version-min": {}, "topology": {}, "tun-ipv6": {}, "tun-mtu": {}, "txqueuelen": {},
	"tun-mtu-extra": {}, "verb": {}, "verify-x509-name": {}, "x509-username-field": {},
}

// checkProviders allows the built-in OpenSSL provider names. A path would load a module into root OpenVPN.
func checkProviders(args string) error {
	fields := strings.Fields(args)
	if len(fields) < 1 || len(fields) > 2 {
		return fmt.Errorf("openvpn: providers allows only default or legacy")
	}
	for _, field := range fields {
		switch strings.ToLower(field) {
		case "default", "legacy":
		default:
			return fmt.Errorf("openvpn: providers %q is refused", field)
		}
	}
	return nil
}

// sanitizeBlock runs the same allowlist over a <connection> body. Nested blocks are refused.
func sanitizeBlock(parent, body, fetchRoot string) (string, []string, error) {
	items, err := scan(body)
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	var stripped []string
	for _, it := range items {
		switch it.kind {
		case kindComment, kindBlank:
			continue
		case kindBlock:
			return "", nil, fmt.Errorf("openvpn: refused nested block <%s>", it.key)
		case kindLine:
			key, args := splitKey(it.raw)
			if key == "config" {
				return "", nil, fmt.Errorf("openvpn: refused directive %q inside <connection>", key)
			}
			if strip, _ := strippedDirective(key); strip {
				stripped = append(stripped, key)
				continue
			}
			if key == "allow-compression" && strings.TrimSpace(args) != "no" {
				stripped = append(stripped, key)
				continue
			}
			if !allowedLine(key) {
				return "", nil, fmt.Errorf("openvpn: refused unknown directive %q", key)
			}
			if key == "providers" {
				if err := checkProviders(args); err != nil {
					return "", nil, err
				}
			}
			if pathDirective(key) {
				line, err := rewritePathLine(parent, it.raw, fetchRoot)
				if err != nil {
					return "", nil, err
				}
				b.WriteString(line + "\n")
				continue
			}
			b.WriteString(strings.TrimRight(it.raw, "\r") + "\n")
		}
	}
	return b.String(), stripped, nil
}

func allowedBlock(key string) bool {
	switch key {
	case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "dh", "extra-certs", "pkcs12", "secret", "connection":
		return true
	default:
		return false
	}
}

func pathDirective(key string) bool {
	switch key {
	case "ca", "cert", "key", "dh", "pkcs12", "crl-verify", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret":
		return true
	default:
		return false
	}
}

// rewritePathLine makes path arguments absolute against the file that contained them.
// tls-auth keeps its direction field. A github fetch rewrites /etc/openvpn/ to the fetch root
// so the sanitized copy in /run/openvpn/config.ovpn still finds the certs.
func rewritePathLine(parent, raw, fetchRoot string) (string, error) {
	fields, err := splitQuoted(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if len(fields) < 2 {
		return strings.TrimSpace(raw), nil
	}
	fields[1] = remapPath(parent, fields[1], fetchRoot)
	return joinFields(fields), nil
}

func remapPath(parent, p, fetchRoot string) string {
	if filepath.IsAbs(p) {
		cleaned := filepath.Clean(p)
		if fetchRoot != "" && underRoot(fetchRoot, parent) {
			const baked = "/etc/openvpn"
			if cleaned == baked || strings.HasPrefix(cleaned, baked+string(os.PathSeparator)) {
				rest := strings.TrimPrefix(cleaned, baked)
				rest = strings.TrimPrefix(rest, string(os.PathSeparator))
				return filepath.Join(fetchRoot, rest)
			}
		}
		return cleaned
	}
	return filepath.Clean(filepath.Join(filepath.Dir(parent), p))
}

func underRoot(root, file string) bool {
	root = filepath.Clean(root)
	file = filepath.Clean(file)
	if file == root {
		return true
	}
	return strings.HasPrefix(file, root+string(os.PathSeparator))
}

func splitQuoted(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	wrote := false
	flush := func() {
		if wrote {
			out = append(out, cur.String())
			cur.Reset()
			wrote = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '"':
			inQuote = false
		case inQuote && c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			wrote = true
		case inQuote:
			cur.WriteByte(c)
			wrote = true
		case c == '"':
			inQuote = true
			wrote = true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
			wrote = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("openvpn: unmatched quote")
	}
	flush()
	return out, nil
}

func joinFields(fields []string) string {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(f, " \t") {
			b.WriteByte('"')
			b.WriteString(f)
			b.WriteByte('"')
		} else {
			b.WriteString(f)
		}
	}
	return b.String()
}

func includePath(parent, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("openvpn: config include is empty")
	}
	var p string
	if filepath.IsAbs(ref) {
		p = filepath.Clean(ref)
	} else {
		p = filepath.Clean(filepath.Join(filepath.Dir(parent), ref))
	}
	base := filepath.Clean(filepath.Dir(parent))
	if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("openvpn: config include %s escapes %s", ref, base)
	}
	return p, nil
}

func inlineAuth(body string) (string, string, error) {
	var lines []string
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		lines = append(lines, ln)
	}
	if len(lines) < 2 {
		return "", "", fmt.Errorf("openvpn: inline auth-user-pass needs two lines")
	}
	return lines[0], lines[1], nil
}

type kind int

const (
	kindLine kind = iota
	kindBlock
	kindComment
	kindBlank
)

type item struct {
	kind kind
	key  string
	raw  string
	body string
}

func scan(text string) ([]item, error) {
	lines := strings.Split(text, "\n")
	var out []item
	for i := 0; i < len(lines); i++ {
		ln := strings.TrimRight(lines[i], "\r")
		trim := strings.TrimSpace(ln)
		if trim == "" {
			out = append(out, item{kind: kindBlank})
			continue
		}
		if strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			out = append(out, item{kind: kindComment, raw: ln})
			continue
		}
		if strings.HasPrefix(trim, "<") && strings.HasSuffix(trim, ">") && !strings.HasPrefix(trim, "</") {
			key := strings.TrimSuffix(strings.TrimPrefix(trim, "<"), ">")
			key = strings.TrimSpace(key)
			var body strings.Builder
			found := false
			for i++; i < len(lines); i++ {
				t := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
				if t == "</"+key+">" {
					found = true
					break
				}
				body.WriteString(strings.TrimRight(lines[i], "\r"))
				body.WriteByte('\n')
			}
			if !found {
				return nil, fmt.Errorf("openvpn: unclosed <%s>", key)
			}
			out = append(out, item{kind: kindBlock, key: key, body: body.String()})
			continue
		}
		key, _ := splitKey(ln)
		out = append(out, item{kind: kindLine, raw: ln, key: key})
	}
	return out, nil
}

func splitKey(line string) (string, string) {
	line = strings.TrimSpace(line)
	i := strings.IndexFunc(line, unicode.IsSpace)
	if i < 0 {
		return strings.ToLower(line), ""
	}
	return strings.ToLower(line[:i]), line[i:]
}

// rejectOpts fails closed on flags that reintroduce scripts, a second config, or compression.
// --up-delay and --up-restart are not --up.
func rejectOpts(opts []string) error {
	deny := map[string]bool{
		"script-security": true, "up": true, "down": true, "route-up": true, "route-pre-down": true,
		"ipchange": true, "client-connect": true, "client-disconnect": true, "learn-address": true,
		"auth-user-pass-verify": true, "tls-verify": true, "plugin": true, "management": true,
		"askpass": true, "daemon": true, "writepid": true, "user": true, "group": true,
		"config": true, "cd": true, "auth-user-pass": true, "comp-lzo": true, "compress": true, "comp-noadapt": true,
		"allow-compression": true, "dns-updown": true, "chroot": true, "log": true, "log-append": true,
		"route-noexec": true, "ifconfig-noexec": true, "providers": true,
		"status": true, "replay-persist": true, "tmp-dir": true, "setenv": true, "setenv-safe": true,
		"tls-crypt-v2-verify": true, "client-crresponse": true,
	}
	for _, a := range opts {
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if deny[name] {
			return fmt.Errorf("openvpn: refused option --%s", name)
		}
	}
	return nil
}

// SplitOpts tokenizes OPENVPN_OPTS on whitespace, with double quotes.
func SplitOpts(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '"':
			inQuote = false
		case inQuote:
			cur.WriteByte(c)
		case c == '"':
			inQuote = true
		case c == ' ' || c == '\t' || c == '\n':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("openvpn: unmatched quote in OPENVPN_OPTS")
	}
	flush()
	return out, nil
}
