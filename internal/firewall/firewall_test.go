package firewall

import (
	"net/netip"
	"testing"
)

func TestDefaultRouteAndPrefix(t *testing.T) {
	gw, dev, err := DefaultRoute4("default via 192.168.1.1 dev eth0 metric 100\n")
	if err != nil || gw.String() != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("route: %v %s %s", err, gw, dev)
	}
	p, err := FirstInetPrefix("2: eth0: <BROADCAST>\n    inet 10.7.0.15/24 brd 10.7.0.255 scope global eth0\n")
	if err != nil || p.String() != "10.7.0.0/24" {
		t.Fatalf("prefix: %v %s", err, p)
	}
}

func TestRejectDefaultRouteCIDR(t *testing.T) {
	p := netip.MustParsePrefix("0.0.0.0/0")
	if err := ReplaceRoute(p, netip.MustParseAddr("192.168.1.1"), "eth0"); err == nil {
		t.Fatal("expected /0 to be refused before ip runs")
	}
}

func TestValidateIf(t *testing.T) {
	if err := validateIf("tun0"); err != nil {
		t.Fatal(err)
	}
	if err := validateIf("tun0;rm"); err == nil {
		t.Fatal("expected bad interface")
	}
}
