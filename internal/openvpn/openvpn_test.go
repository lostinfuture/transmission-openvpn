package openvpn

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lookup(host string) ([]netip.Addr, error) {
	switch host {
	case "example.com":
		return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11")}, nil
	case "other.example":
		return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
	default:
		return nil, os.ErrNotExist
	}
}

func TestContribNobody(t *testing.T) {
	res, err := Prepare("testdata/contrib-nobody.ovpn", nil, true, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"user nobody", "group nobody", "daemon", "script-security 3", "up /etc/openvpn/up.sh", "route-up /bin/true", "dns-updown /evil.sh", "comp-lzo", "example.com"} {
		if strings.Contains(res.Config, bad) {
			t.Fatalf("sanitized config still contains %q\n%s", bad, res.Config)
		}
	}
	if strings.Count(res.Config, "script-security") != 1 || !strings.Contains(res.Config, "script-security 2") {
		t.Fatalf("script-security lines:\n%s", res.Config)
	}
	if !strings.Contains(res.Config, `route-up "/usr/bin/ovpn-supervisor hook-up"`) || !strings.Contains(res.Config, `route-pre-down "/usr/bin/ovpn-supervisor hook-down"`) {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "dns-updown disable") || !strings.Contains(res.Config, "allow-compression no") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "persist-tun") || !strings.Contains(res.Config, "BEGIN CERTIFICATE") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "remote 203.0.113.10 1194 udp") || !strings.Contains(res.Config, "remote 203.0.113.11 1194 udp") {
		t.Fatal(res.Config)
	}
	if len(res.Endpoints) != 2 {
		t.Fatalf("endpoints = %+v", res.Endpoints)
	}
}

func TestRejectOpts(t *testing.T) {
	if _, err := Prepare("testdata/contrib-nobody.ovpn", []string{"--route-up", "/bin/true"}, true, lookup, false); err == nil {
		t.Fatal("expected --route-up to be refused")
	}
	if _, err := Prepare("testdata/contrib-nobody.ovpn", []string{"--config", "/tmp/other.ovpn"}, true, lookup, false); err == nil {
		t.Fatal("expected --config to be refused")
	}
	if _, err := Prepare("testdata/contrib-nobody.ovpn", []string{"--up-delay"}, true, lookup, false); err != nil {
		t.Fatal(err)
	}
	opts, err := SplitOpts(`--tun-mtu 1500 --pull-filter "ignore redirect-gateway"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 4 || opts[2] != "--pull-filter" || opts[3] != "ignore redirect-gateway" {
		t.Fatalf("opts = %#v", opts)
	}
}

func TestNestedConfigRefused(t *testing.T) {
	dir := t.TempDir()
	inner := filepath.Join(dir, "inner.ovpn")
	if err := os.WriteFile(inner, []byte("config deeper.ovpn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outer := filepath.Join(dir, "outer.ovpn")
	if err := os.WriteFile(outer, []byte("client\ndev tun\nconfig inner.ovpn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(outer, nil, false, lookup, false); err == nil {
		t.Fatal("expected nested config to fail")
	}
}

func TestIncludeStripsAndEscapes(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "part.ovpn")
	body := "remote other.example 443 tcp\nuser nobody\n<connection>\nremote example.com 1194\n</connection>\n"
	if err := os.WriteFile(inc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	outer := filepath.Join(dir, "outer.ovpn")
	if err := os.WriteFile(outer, []byte("client\ndev tun\nproto udp\nconfig part.ovpn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(outer, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "nobody") || strings.Contains(res.Config, "\nconfig ") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "remote 203.0.113.20 443 tcp") || !strings.Contains(res.Config, "remote 203.0.113.10 1194 udp") {
		t.Fatal(res.Config)
	}
	outside := filepath.Join(dir, "escape.ovpn")
	if err := os.WriteFile(outside, []byte("client\ndev tun\nconfig "+filepath.Join("..", "passwd")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(outside, nil, false, lookup, false); err == nil {
		t.Fatal("expected include escape to fail")
	}
}

func TestAbsolutizeRelativeCA(t *testing.T) {
	dir := t.TempDir()
	body := "client\ndev tun\nca ca.crt\ntls-auth ta.key 1\nremote 203.0.113.10 1194 udp\ncomp-noadapt\nping-exit 30\n"
	path := filepath.Join(dir, "c.ovpn")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "comp-noadapt") || !strings.Contains(res.Config, "ping-exit 30") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "ca "+filepath.Join(dir, "ca.crt")+"\n") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "tls-auth "+filepath.Join(dir, "ta.key")+" 1\n") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "allow-compression no") {
		t.Fatal(res.Config)
	}
}

func TestFetchRootRewritesBakedPrefix(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "blackvpn")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.ovpn")
	body := "client\ndev tun\nca /etc/openvpn/blackvpn/ssl/ca.crt\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := prepare(path, nil, false, lookup, false, root)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "blackvpn", "ssl", "ca.crt")
	if !strings.Contains(res.Config, "ca "+want+"\n") {
		t.Fatal(res.Config)
	}
	plain, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.Config, "ca /etc/openvpn/blackvpn/ssl/ca.crt\n") {
		t.Fatal(plain.Config)
	}
}

func TestRemoteInlineComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	body := "client\ndev tun\nproto udp # tunnel\nremote example.com 1194 # - Your server IP and OpenVPN Port\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "remote 203.0.113.10 1194 udp\n") {
		t.Fatal(res.Config)
	}
}

func TestTypoCipherFallbackRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	body := "client\ndev tun\ndata-ciphers-fallbacks AES-256-GCM\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, nil, false, lookup, false); err == nil {
		t.Fatal("expected data-ciphers-fallbacks to be refused")
	}
}

func TestMissingCreds(t *testing.T) {
	if _, err := Prepare("testdata/contrib-nobody.ovpn", nil, false, lookup, false); err == nil {
		t.Fatal("expected missing credentials to fail")
	}
}

func TestProtoAfterRemote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	body := "client\ndev tun\nremote example.com 443\nproto tcp\nremote-random-hostname\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "remote 203.0.113.10 443 tcp\n") || strings.Contains(res.Config, " 443 udp") {
		t.Fatal(res.Config)
	}
	if strings.Contains(res.Config, "remote-random-hostname") {
		t.Fatal(res.Config)
	}
	if len(res.Endpoints) != 2 || res.Endpoints[0].Proto != "tcp" || res.Endpoints[0].Port != 443 {
		t.Fatalf("%+v", res.Endpoints)
	}
}

func TestConnectionStripsScripts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	body := "client\ndev tun\nremote 203.0.113.10 1194 udp\n<connection>\nremote other.example 1194\nproto tcp\nup /tmp/x.sh\nproviders /config/evil\n</connection>\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, nil, false, lookup, false); err == nil {
		t.Fatal("expected providers path inside connection to fail")
	}
	body = "client\ndev tun\nremote 203.0.113.10 1194 udp\n<connection>\nremote other.example 1194\nproto tcp\nup /tmp/x.sh\n</connection>\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "up /tmp") || strings.Contains(res.Config, "/tmp/x.sh") {
		t.Fatal(res.Config)
	}
	if !strings.Contains(res.Config, "remote 203.0.113.20 1194 tcp\n") {
		t.Fatal(res.Config)
	}
}

func TestProvidersAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	evil := "client\ndev tun\nproviders /config/evil\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(evil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, nil, false, lookup, false); err == nil {
		t.Fatal("expected providers path to fail")
	}
	ok := "client\ndev tun\nproviders legacy\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "providers legacy\n") {
		t.Fatal(res.Config)
	}
	both := "client\ndev tun\nproviders legacy default\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(both), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = Prepare(path, nil, false, lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "providers legacy default\n") {
		t.Fatal(res.Config)
	}
	bad := "client\ndev tun\nproviders legacy custom\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(path, nil, false, lookup, false); err == nil {
		t.Fatal("expected an unknown providers name to fail")
	}
	if _, err := Prepare(path, []string{"--providers", "legacy"}, false, lookup, false); err == nil {
		t.Fatal("expected --providers to be refused")
	}
	if _, err := Prepare(path, []string{"--route-noexec"}, false, lookup, false); err == nil {
		t.Fatal("expected --route-noexec to be refused")
	}
}
