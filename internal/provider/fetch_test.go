package provider

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSkipsScriptsAndMaterializesLinks(t *testing.T) {
	prefix := "vpn-configs-contrib-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/openvpn"
	clean := tarGz(t, map[string]string{
		prefix + "/good/default.ovpn":   "client\ndev tun\n",
		prefix + "/good/ca.crt":         "CERT",
		prefix + "/good/skip.sh":        "echo no\n",
		prefix + "/good/note.py":        "print(1)\n",
		prefix + "/custom/default.ovpn": "client\n",
	}, map[string]string{
		prefix + "/good/alias.ovpn": "default.ovpn",
		prefix + "/good/nl.ovpn":    "default.ovpn\n",
	})
	dest := t.TempDir()
	gz, err := gzip.NewReader(bytes.NewReader(clean))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	if err := extractContrib(gz, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "custom")); !os.IsNotExist(err) {
		t.Fatal("custom should be skipped")
	}
	if _, err := os.Stat(filepath.Join(dest, "good", "skip.sh")); !os.IsNotExist(err) {
		t.Fatal("script should be skipped")
	}
	if _, err := os.Stat(filepath.Join(dest, "good", "note.py")); !os.IsNotExist(err) {
		t.Fatal("python should be skipped")
	}
	body, err := os.ReadFile(filepath.Join(dest, "good", "alias.ovpn"))
	if err != nil || string(body) != "client\ndev tun\n" {
		t.Fatalf("alias: %q %v", body, err)
	}
	body, err = os.ReadFile(filepath.Join(dest, "good", "nl.ovpn"))
	if err != nil || string(body) != "client\ndev tun\n" {
		t.Fatalf("newline link: %q %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "good", "ca.crt")); err != nil {
		t.Fatal(err)
	}

	bad := tarGz(t, map[string]string{prefix + "/good/../escape.ovpn": "nope\n"}, nil)
	gz, err = gzip.NewReader(bytes.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	if err := extractContrib(gz, t.TempDir()); err == nil {
		t.Fatal("expected escape rejection")
	}
}

func TestExtractCountsSymlinkBytes(t *testing.T) {
	prefix := "vpn-configs-contrib-" + strings.Repeat("b", 40) + "/openvpn"
	body := strings.Repeat("x", maxFile)
	files := map[string]string{prefix + "/good/default.ovpn": body}
	links := map[string]string{}
	for i := 0; i < 12; i++ {
		links[fmt.Sprintf("%s/good/l%d.ovpn", prefix, i)] = "default.ovpn"
	}
	raw := tarGz(t, files, links)
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	if err := extractContrib(gz, t.TempDir()); err == nil {
		t.Fatal("expected symlink bodies to count toward the uncompressed cap")
	}
}

func TestFetchGitHubCapsAndRevision(t *testing.T) {
	rev := strings.Repeat("a", 40)
	prefix := "vpn-configs-contrib-" + rev + "/openvpn"
	blob := tarGz(t, map[string]string{prefix + "/good/default.ovpn": "client\n"}, nil)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/haugene/vpn-configs-contrib/tar.gz/"+rev {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(blob)
	}))
	defer srv.Close()
	old := codeloadBase
	codeloadBase = srv.URL
	t.Cleanup(func() { codeloadBase = old })

	if err := fetchGitHub(context.Background(), srv.Client(), "haugene/vpn-configs-contrib", "main", t.TempDir(), MaxTarball); err == nil {
		t.Fatal("expected branch rejection")
	}
	if hits != 0 {
		t.Fatalf("branch revision made %d requests", hits)
	}
	dest := t.TempDir()
	if err := fetchGitHub(context.Background(), srv.Client(), "haugene/vpn-configs-contrib", rev, dest, MaxTarball); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "good", "default.ovpn")); err != nil {
		t.Fatal(err)
	}
	if err := fetchGitHub(context.Background(), srv.Client(), "haugene/vpn-configs-contrib", rev, t.TempDir(), 8); err == nil {
		t.Fatal("expected size cap")
	}
	if err := ValidRepo("haugene/../vpn"); err == nil {
		t.Fatal("expected repo rejection")
	}
}

func TestCheckSnapshot(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "airvpn")
	bad := filepath.Join(root, "freedomip")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	okBody := "client\ndev tun\nremote 203.0.113.10 1194\n"
	if err := os.WriteFile(filepath.Join(good, "default.ovpn"), []byte("not-a-directive-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "real.ovpn"), []byte(okBody), 0o644); err != nil {
		t.Fatal(err)
	}
	// The pointer names real.ovpn, so the default itself sanitizes after follow.
	if err := os.WriteFile(filepath.Join(good, "default.ovpn"), []byte("real.ovpn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "legacy.ovpn"), []byte("client\ndev tun\ndata-ciphers-fallbacks AES-256-GCM\nremote 203.0.113.10 1194\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckSnapshot(root)
	if err == nil || !strings.Contains(err.Error(), "freedomip") {
		t.Fatal(err)
	}
	if err := os.RemoveAll(bad); err != nil {
		t.Fatal(err)
	}
	if err := CheckSnapshot(root); err != nil {
		t.Fatal(err)
	}
}

func tarGz(t *testing.T, files map[string]string, links map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		hdr := &tar.Header{Name: name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: target}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
