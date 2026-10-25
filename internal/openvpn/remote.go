package openvpn

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func rewriteRemotes(text string, lookup Lookup, ipv6 bool) (string, []Endpoint, error) {
	items, err := scan(text)
	if err != nil {
		return "", nil, err
	}
	proto, port := finalProtoPort(items, "udp", 1194)
	var b strings.Builder
	var eps []Endpoint
	seen := map[string]bool{}
	add := func(host string, p int, pr string) error {
		addrs, err := expand(host, lookup, ipv6)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			fmt.Fprintf(&b, "remote %s %d %s\n", addr, p, pr)
			key := addr + "/" + pr + "/" + strconv.Itoa(p)
			if !seen[key] {
				seen[key] = true
				eps = append(eps, Endpoint{Addr: addr, Proto: pr, Port: p})
			}
		}
		return nil
	}
	for _, it := range items {
		switch it.kind {
		case kindBlank, kindComment:
			continue
		case kindBlock:
			if it.key != "connection" {
				fmt.Fprintf(&b, "<%s>\n%s</%s>\n", it.key, it.body, it.key)
				continue
			}
			body, inner, err := rewriteConnection(it.body, proto, port, lookup, ipv6)
			if err != nil {
				return "", nil, err
			}
			fmt.Fprintf(&b, "<connection>\n%s</connection>\n", body)
			for _, ep := range inner {
				key := ep.Addr + "/" + ep.Proto + "/" + strconv.Itoa(ep.Port)
				if !seen[key] {
					seen[key] = true
					eps = append(eps, ep)
				}
			}
		case kindLine:
			key, args := splitKey(it.raw)
			switch key {
			case "proto", "port", "rport":
				b.WriteString(strings.TrimSpace(it.raw) + "\n")
			case "remote-random-hostname":
				continue
			case "remote":
				host, p, pr, err := parseRemote(args, port, proto)
				if err != nil {
					return "", nil, err
				}
				if err := add(host, p, pr); err != nil {
					return "", nil, err
				}
			default:
				b.WriteString(strings.TrimRight(it.raw, "\r") + "\n")
			}
		}
	}
	if len(eps) == 0 {
		return "", nil, fmt.Errorf("openvpn: config has no usable remote")
	}
	return b.String(), eps, nil
}

func finalProtoPort(items []item, proto string, port int) (string, int) {
	for _, it := range items {
		if it.kind != kindLine {
			continue
		}
		key, args := splitKey(it.raw)
		switch key {
		case "proto":
			proto = canonProto(firstArg(args))
		case "port", "rport":
			n, err := strconv.Atoi(firstArg(args))
			if err == nil && n >= 1 && n <= 65535 {
				port = n
			}
		}
	}
	return proto, port
}

func rewriteConnection(body string, proto string, port int, lookup Lookup, ipv6 bool) (string, []Endpoint, error) {
	var prelim []item
	for _, ln := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(ln)
		if trim == "" {
			continue
		}
		prelim = append(prelim, item{kind: kindLine, raw: trim})
	}
	proto, port = finalProtoPort(prelim, proto, port)
	var b strings.Builder
	var eps []Endpoint
	for _, ln := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(ln)
		if trim == "" {
			continue
		}
		key, args := splitKey(trim)
		switch key {
		case "proto", "port", "rport":
			fmt.Fprintf(&b, "%s\n", strings.TrimSpace(ln))
		case "remote-random-hostname":
			continue
		case "remote":
			host, p, pr, err := parseRemote(args, port, proto)
			if err != nil {
				return "", nil, err
			}
			addrs, err := expand(host, lookup, ipv6)
			if err != nil {
				return "", nil, err
			}
			for _, addr := range addrs {
				fmt.Fprintf(&b, "remote %s %d %s\n", addr, p, pr)
				eps = append(eps, Endpoint{Addr: addr, Proto: pr, Port: p})
			}
		default:
			fmt.Fprintf(&b, "%s\n", strings.TrimSpace(ln))
		}
	}
	return b.String(), eps, nil
}

func parseRemote(args string, defPort int, defProto string) (string, int, string, error) {
	fields := commentFields(args)
	if len(fields) == 0 {
		return "", 0, "", fmt.Errorf("openvpn: remote is missing a host")
	}
	host := strings.Trim(fields[0], "[]")
	port := defPort
	proto := canonProto(defProto)
	if len(fields) >= 2 {
		if n, err := strconv.Atoi(fields[1]); err == nil {
			if n < 1 || n > 65535 {
				return "", 0, "", fmt.Errorf("openvpn: bad remote port %q", fields[1])
			}
			port = n
			if len(fields) >= 3 {
				proto = canonProto(fields[2])
			}
		} else {
			proto = canonProto(fields[1])
		}
	}
	if proto != "tcp" && proto != "udp" {
		return "", 0, "", fmt.Errorf("openvpn: remote protocol %q is not tcp or udp", proto)
	}
	return host, port, proto, nil
}

func expand(host string, lookup Lookup, ipv6 bool) ([]string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is6() && !ipv6 {
			return nil, fmt.Errorf("openvpn: remote %s is ipv6 and ENABLE_IPV6 is false", host)
		}
		return []string{ip.String()}, nil
	}
	if lookup == nil {
		return nil, fmt.Errorf("openvpn: no resolver for %s", host)
	}
	addrs, err := lookup(host)
	if err != nil {
		return nil, fmt.Errorf("openvpn: resolve %s: %w", host, err)
	}
	var out []string
	for _, addr := range addrs {
		if addr.Is6() && !ipv6 {
			continue
		}
		if !addr.IsValid() {
			continue
		}
		out = append(out, addr.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("openvpn: %s has no usable address", host)
	}
	return out, nil
}

// commentFields drops an inline # or ; comment. OpenVPN treats the rest of the line as a comment.
func commentFields(args string) []string {
	var out []string
	for _, f := range strings.Fields(args) {
		if strings.HasPrefix(f, "#") || strings.HasPrefix(f, ";") {
			break
		}
		out = append(out, f)
	}
	return out
}

func firstArg(args string) string {
	fields := commentFields(args)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func canonProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "tcp", "tcp-client", "tcp-server", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6", "":
		return "udp"
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}
