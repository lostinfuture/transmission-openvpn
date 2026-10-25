package pia

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// ServerListURL is the public region list. A base64 signature follows the JSON.
	ServerListURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
	udpPort       = 8080
)

// Region is one PIA OpenVPN region.
type Region struct {
	ID          string
	Name        string
	Country     string
	DNS         string
	Auto        bool
	PortForward bool
	Offline     bool
	UDPIP       string
	TCPIP       string
	CN          string
}

// SplitToken matches connect_to_openvpn_with_token.sh when the username is empty.
// The port-forward token stays the full string. Only the OpenVPN login is split.
func SplitToken(token string) (user, pass string) {
	if len(token) <= 62 {
		return token, token
	}
	return token[:62], token[62:]
}

// FetchServers downloads the public server list.
func FetchServers(ctx context.Context, client *http.Client, listURL string) ([]Region, error) {
	if listURL == "" {
		listURL = ServerListURL
	}
	body, err := getLimited(ctx, httpClient(client), listURL, maxJSON, "")
	if err != nil {
		return nil, err
	}
	return ParseServers(strings.NewReader(string(body)))
}

// ParseServers reads the JSON object and ignores a trailing signature.
func ParseServers(r io.Reader) ([]Region, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxJSON+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxJSON {
		return nil, fmt.Errorf("pia: server list exceeds %d bytes", maxJSON)
	}
	var doc struct {
		Regions []rawRegion `json:"regions"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("pia: server list: %w", err)
	}
	if len(doc.Regions) == 0 {
		return nil, fmt.Errorf("pia: empty server list")
	}
	out := make([]Region, 0, len(doc.Regions))
	for _, raw := range doc.Regions {
		reg := Region{
			ID: raw.ID, Name: raw.Name, Country: raw.Country, DNS: raw.DNS,
			Auto: raw.Auto, PortForward: raw.PF, Offline: raw.Offline,
		}
		if len(raw.Servers.UDP) > 0 {
			reg.UDPIP = raw.Servers.UDP[0].IP
			reg.CN = raw.Servers.UDP[0].CN
		}
		if len(raw.Servers.TCP) > 0 {
			reg.TCPIP = raw.Servers.TCP[0].IP
		}
		out = append(out, reg)
	}
	return out, nil
}

// Select picks a region. An empty name prefers the first online auto region with port forwarding.
// A name matches id first, then name, case-insensitively.
func Select(regions []Region, name string) (Region, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		for _, r := range regions {
			if !r.Offline && r.PortForward && r.Auto {
				return r, nil
			}
		}
		for _, r := range regions {
			if !r.Offline && r.Auto {
				return r, nil
			}
		}
		return Region{}, fmt.Errorf("pia: no online auto region")
	}
	var byName *Region
	for i := range regions {
		r := &regions[i]
		if strings.EqualFold(r.ID, name) {
			return *r, nil
		}
		if byName == nil && strings.EqualFold(r.Name, name) {
			cp := *r
			byName = &cp
		}
	}
	if byName != nil {
		return *byName, nil
	}
	return Region{}, fmt.Errorf("pia: region %q not found", name)
}

// ConfigText is a minimal UDP client config. The remote is an IP so OpenVPN does not need DNS.
// The CA is embedded. There is no up/down script.
func ConfigText(r Region, ca []byte) (string, error) {
	if r.UDPIP == "" {
		return "", fmt.Errorf("pia: region %s has no udp server", r.ID)
	}
	if !strings.Contains(string(ca), "BEGIN CERTIFICATE") {
		return "", fmt.Errorf("pia: missing CA")
	}
	pem := string(ca)
	if !strings.HasSuffix(pem, "\n") {
		pem += "\n"
	}
	var b strings.Builder
	b.WriteString("client\n")
	b.WriteString("dev tun\n")
	b.WriteString("resolv-retry infinite\n")
	b.WriteString("nobind\n")
	b.WriteString("persist-key\n")
	b.WriteString("persist-tun\n")
	b.WriteString("cipher aes-256-cbc\n")
	b.WriteString("auth sha256\n")
	b.WriteString("tls-client\n")
	b.WriteString("remote-cert-tls server\n")
	b.WriteString("verb 1\n")
	b.WriteString("reneg-sec 0\n")
	fmt.Fprintf(&b, "remote %s %d udp\n", r.UDPIP, udpPort)
	if r.CN != "" {
		if strings.ContainsAny(r.CN, " \t\r\n") {
			return "", fmt.Errorf("pia: bad server cn %q", r.CN)
		}
		fmt.Fprintf(&b, "verify-x509-name %s name\n", r.CN)
	}
	b.WriteString("<ca>\n")
	b.WriteString(pem)
	b.WriteString("</ca>\n")
	return b.String(), nil
}

type rawRegion struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country"`
	DNS     string `json:"dns"`
	Auto    bool   `json:"auto_region"`
	PF      bool   `json:"port_forward"`
	Offline bool   `json:"offline"`
	Servers struct {
		UDP []struct {
			IP string `json:"ip"`
			CN string `json:"cn"`
		} `json:"ovpnudp"`
		TCP []struct {
			IP string `json:"ip"`
		} `json:"ovpntcp"`
	} `json:"servers"`
}
