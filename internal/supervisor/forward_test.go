package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestForwardMode(t *testing.T) {
	if m, o := forwardMode("protonvpn", "natpmp", false); m != "natpmp" || o {
		t.Fatalf("%s %v", m, o)
	}
	if m, o := forwardMode("protonvpn", "", false); m != "natpmp" || o {
		t.Fatalf("%s %v", m, o)
	}
	if m, o := forwardMode("pia", "", false); m != "pia" || o {
		t.Fatalf("%s %v", m, o)
	}
	if m, o := forwardMode("pia", "natpmp", false); m != "natpmp" || !o {
		t.Fatalf("%s %v", m, o)
	}
	if m, o := forwardMode("pia", "natpmp", true); m != "" || o {
		t.Fatalf("%s %v", m, o)
	}
	if m, o := forwardMode("custom", "natpmp", false); m != "natpmp" || o {
		t.Fatalf("%s %v", m, o)
	}
	if m, _ := forwardMode("nordvpn", "", false); m != "" {
		t.Fatal(m)
	}
}

func TestPIAForwardName(t *testing.T) {
	if got := piaForwardName("amsterdam425", "nl-amsterdam.privacy.network"); got != "amsterdam425" {
		t.Fatal(got)
	}
	if got := piaForwardName("", "nl-amsterdam.privacy.network"); got != "nl-amsterdam.privacy.network" {
		t.Fatal(got)
	}
	if got := piaForwardName("203.0.113.10", "nl-amsterdam.privacy.network"); got != "nl-amsterdam.privacy.network" {
		t.Fatal(got)
	}
}

func TestChildEnvStripsToken(t *testing.T) {
	out := childEnv([]string{"PATH=/bin", "PIA_TOKEN=abc", "OPENVPN_PASSWORD=secret", "OPENVPN_USERNAME=user"})
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "abc") || strings.Contains(joined, "secret") || strings.Contains(joined, "PIA_TOKEN") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "OPENVPN_USERNAME=user") || !strings.Contains(joined, "PATH=/bin") {
		t.Fatal(joined)
	}
}

func TestPIAWait(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	wait, refresh := piaWait(now.Add(-time.Second), now)
	if wait != 0 || !refresh {
		t.Fatalf("expired: %s %v", wait, refresh)
	}
	wait, refresh = piaWait(now.Add(time.Minute), now)
	if refresh || wait != time.Minute {
		t.Fatalf("short: %s %v", wait, refresh)
	}
	wait, refresh = piaWait(now.Add(time.Hour), now)
	if refresh || wait != 15*time.Minute {
		t.Fatalf("long: %s %v", wait, refresh)
	}
}

func TestRPCAuthUsable(t *testing.T) {
	if !rpcAuthUsable(false, "{hash}abc", "") {
		t.Fatal("auth off")
	}
	if rpcAuthUsable(true, "{hash}abc", "") {
		t.Fatal("hashed file password")
	}
	if rpcAuthUsable(true, "plaintext", "") {
		t.Fatal("file password is not sent")
	}
	if !rpcAuthUsable(true, "{hash}abc", "env-secret") {
		t.Fatal("env password")
	}
}

func TestFirstNonIPRemote(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.ovpn")
	body := "remote 10.0.0.1 1194 udp\nremote de-berlin.privacy.network 1194 udp\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := firstNonIPRemote(path); got != "de-berlin.privacy.network" {
		t.Fatal(got)
	}
}
