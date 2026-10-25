package control

import (
	"net/netip"
	"strconv"
	"strings"
)

// DNSFromEnv collects pushed resolvers from OpenVPN's route-up environment.
// Classic pushes arrive as foreign_option_N=dhcp-option DNS <addr>.
// OpenVPN 2.7 also exports dns_server_N_address_M when dns-updown runs.
func DNSFromEnv(env []string) (servers, search []string) {
	seen := map[string]bool{}
	add := func(addr string) {
		addr = strings.Trim(addr, "[]")
		ip, err := netip.ParseAddr(addr)
		if err != nil || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		servers = append(servers, ip.String())
	}
	for _, e := range env {
		key, val, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(key, "foreign_option_"):
			fields := strings.Fields(val)
			if len(fields) >= 3 && fields[0] == "dhcp-option" {
				switch fields[1] {
				case "DNS", "DNS6":
					add(fields[2])
				case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER-DOMAIN-SUFFIX":
					if fields[2] != "" {
						search = append(search, fields[2])
					}
				}
			}
		case strings.Contains(key, "_address_"):
			if strings.HasPrefix(key, "dns_server_") {
				// Values look like "10.8.0.1" or "10.8.0.1 53".
				fields := strings.Fields(val)
				if len(fields) > 0 {
					add(fields[0])
				}
			}
		}
	}
	return servers, search
}

// HookUpFromEnv builds the hook-up request OpenVPN's route-up process sends.
func HookUpFromEnv(env []string) Up {
	m := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	dns, search := DNSFromEnv(env)
	port, _ := strconv.Atoi(m["trusted_port"])
	redir := m["redirect_gateway"]
	up := Up{
		Op:                "hook-up",
		Dev:               m["dev"],
		IfconfigLocal:     m["ifconfig_local"],
		IfconfigRemote:    m["ifconfig_remote"],
		IfconfigNetmask:   m["ifconfig_netmask"],
		IfconfigIPv6Local: m["ifconfig_ipv6_local"],
		RouteVPNGateway:   m["route_vpn_gateway"],
		Proto:             normalizeProto(m["proto"]),
		TrustedIP:         m["trusted_ip"],
		TrustedPort:       port,
		RedirectGateway:   redir != "" && redir != "0",
		DNS:               dns,
		Search:            search,
		TunMTU:            m["tun_mtu"],
		LinkMTU:           m["link_mtu"],
		ScriptContext:     m["script_context"],
	}
	if up.ScriptContext == "" {
		up.ScriptContext = "init"
	}
	return up
}

func normalizeProto(p string) string {
	switch p {
	case "tcp", "tcp-client", "tcp-server", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6", "":
		return "udp"
	default:
		return p
	}
}
