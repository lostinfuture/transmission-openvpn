package pia

import (
	"os"
	"strings"
	"testing"
)

func TestSplitToken(t *testing.T) {
	user, pass := SplitToken("short")
	if user != "short" || pass != "short" {
		t.Fatalf("%q %q", user, pass)
	}
	token := strings.Repeat("a", 62) + "bc"
	user, pass = SplitToken(token)
	if user != strings.Repeat("a", 62) || pass != "bc" {
		t.Fatalf("%q %q", user, pass)
	}
	user, pass = SplitToken(strings.Repeat("a", 62))
	if user != pass || len(user) != 62 {
		t.Fatalf("%d %d", len(user), len(pass))
	}
}

func TestSelectAndConfig(t *testing.T) {
	b, err := os.ReadFile("testdata/servers.json")
	if err != nil {
		t.Fatal(err)
	}
	regions, err := ParseServers(strings.NewReader(string(b) + "\n\nQUJDRA==\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Select(regions, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "nl_amsterdam" || got.DNS != "nl-amsterdam.privacy.network" || got.UDPIP != "195.78.54.102" || got.CN != "amsterdam425" {
		t.Fatalf("%+v", got)
	}
	named, err := Select(regions, "NL_Amsterdam")
	if err != nil || named.ID != "nl_amsterdam" {
		t.Fatal(err, named)
	}
	byName, err := Select(regions, "netherlands")
	if err != nil || byName.ID != "nl_amsterdam" {
		t.Fatal(err, byName)
	}
	nopf, err := Select(regions, "auto_nopf")
	if err != nil || nopf.PortForward {
		t.Fatal(err, nopf)
	}
	if _, err := Select(regions, "missing"); err == nil {
		t.Fatal("expected missing region")
	}
	text, err := ConfigText(got, CA())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "remote 195.78.54.102 8080 udp\n") || !strings.Contains(text, "verify-x509-name amsterdam425 name\n") {
		t.Fatal(text)
	}
	if !strings.Contains(text, "dev tun\n") || strings.Contains(text, "tun06") {
		t.Fatal("dev line")
	}
	if strings.Contains(text, "script-security") || strings.Contains(text, "/opt/piavpn") {
		t.Fatal(text)
	}
	if !strings.Contains(text, "BEGIN CERTIFICATE") || !strings.Contains(text, "END CERTIFICATE") {
		t.Fatal("ca missing")
	}
}

func TestCASubject(t *testing.T) {
	cert, err := parseCA()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "Private Internet Access" {
		t.Fatal(cert.Subject.CommonName)
	}
	pool, err := CAPool()
	if err != nil || pool == nil {
		t.Fatal(err)
	}
}
