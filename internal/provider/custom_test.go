package provider

import "testing"

func TestCustomPath(t *testing.T) {
	p, err := CustomPath("vpn")
	if err != nil || p != "/etc/openvpn/custom/vpn.ovpn" {
		t.Fatalf("%s %v", p, err)
	}
	p, err = CustomPath("")
	if err != nil || p != "/etc/openvpn/custom/default.ovpn" {
		t.Fatalf("%s %v", p, err)
	}
	if _, err := CustomPath("../secret"); err == nil {
		t.Fatal("expected rejection")
	}
}
