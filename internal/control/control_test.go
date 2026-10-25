package control

import (
	"net"
	"path/filepath"
	"testing"
)

func TestDNSFromEnv(t *testing.T) {
	env := []string{
		"foreign_option_1=dhcp-option DNS 10.8.0.1",
		"foreign_option_2=dhcp-option DNS6 2001:db8::1",
		"foreign_option_3=dhcp-option DOMAIN example.net",
		"dns_server_1_address_1=10.8.0.1",
		"dns_server_1_address_2=10.9.0.1 53",
		"dev=tun0",
	}
	servers, search := DNSFromEnv(env)
	if len(servers) != 3 || servers[0] != "10.8.0.1" || servers[1] != "2001:db8::1" || servers[2] != "10.9.0.1" {
		t.Fatalf("servers = %#v", servers)
	}
	if len(search) != 1 || search[0] != "example.net" {
		t.Fatalf("search = %#v", search)
	}
	up := HookUpFromEnv(append(env, "ifconfig_local=10.8.0.2", "ifconfig_netmask=255.255.255.0", "route_vpn_gateway=10.8.0.1", "redirect_gateway=1", "proto=udp"))
	if up.Gateway() != "10.8.0.1" {
		t.Fatalf("gateway = %q", up.Gateway())
	}
	if up.IfconfigRemote != "" {
		t.Fatalf("subnet topology should leave ifconfig_remote empty, got %q", up.IfconfigRemote)
	}
	if !up.RedirectGateway || up.Dev != "tun0" || up.Proto != "udp" {
		t.Fatalf("up = %+v", up)
	}
}

func TestCallRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go Serve(ln, func(req []byte) Reply {
		if string(req) == "" {
			return Reply{Error: "empty"}
		}
		return Reply{OK: true}
	})
	rep, err := Call(sock, Up{Op: "hook-up", Dev: "tun0"})
	if err != nil || !rep.OK {
		t.Fatalf("call: %v %+v", err, rep)
	}
}
