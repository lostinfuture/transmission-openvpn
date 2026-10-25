package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lostinfuture/transmission-openvpn/internal/openvpn"
)

func TestFetchRootMatchesSanitizer(t *testing.T) {
	if FetchRoot != openvpn.FetchedRoot {
		t.Fatalf("fetch root %s != sanitizer %s", FetchRoot, openvpn.FetchedRoot)
	}
	if MaxTarball != 32<<20 {
		t.Fatalf("cap %d", MaxTarball)
	}
}

func TestResolveNestedAndDefault(t *testing.T) {
	root := t.TempDir()
	prov := filepath.Join(root, "privatevpn")
	nested := filepath.Join(prov, "dedicated-strong")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	sydney := filepath.Join(nested, "AU Sydney.ovpn")
	if err := os.WriteFile(sydney, []byte("client\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prov, "other.ovpn"), []byte("client\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prov, "default.ovpn"), []byte("other.ovpn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(root, "PrivateVPN", "", func(int) (int, error) { return 0, nil })
	if err != nil || got != filepath.Join(prov, "other.ovpn") {
		t.Fatalf("default pointer: %s %v", got, err)
	}
	got, err = Resolve(root, "privatevpn", "dedicated-strong/AU Sydney", nil)
	if err != nil || got != sydney {
		t.Fatalf("nested: %s %v", got, err)
	}
	got, err = Resolve(root, "privatevpn", "AU Sydney", nil)
	if err != nil || got != sydney {
		t.Fatalf("basename: %s %v", got, err)
	}
	if _, err := Resolve(root, "privatevpn", "../secret", nil); err == nil {
		t.Fatal("expected .. rejection")
	}
	got, err = Resolve(root, "privatevpn", "other, AU Sydney", func(n int) (int, error) {
		if n != 2 {
			t.Fatalf("n=%d", n)
		}
		return 1, nil
	})
	if err != nil || got != sydney {
		t.Fatalf("pick: %s %v", got, err)
	}
	for _, sub := range []string{"a", "b"} {
		dir := filepath.Join(prov, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "twin.ovpn"), []byte("client\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Resolve(root, "privatevpn", "twin", nil); err == nil {
		t.Fatal("expected ambiguous basename")
	}
	if _, err := Resolve(root, "missing", "", nil); err == nil || !strings.Contains(err.Error(), "privatevpn") {
		t.Fatalf("missing provider: %v", err)
	}
}

func TestNoDefaultNamesChoices(t *testing.T) {
	root := t.TempDir()
	prov := filepath.Join(root, "smartdnsproxy")
	if err := os.MkdirAll(prov, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		name := "s" + string(rune('a'+(i%26))) + string(rune('a'+(i/26))) + ".ovpn"
		if err := os.WriteFile(filepath.Join(prov, name), []byte("client\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := Resolve(root, "smartdnsproxy", "", nil)
	if err == nil || !strings.Contains(err.Error(), "list-providers") {
		t.Fatal(err)
	}
}

func TestWriteListMissingRoot(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteList(&buf, filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "custom\n" {
		t.Fatalf("%q", buf.String())
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "airvpn"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "airvpn", "default.ovpn"), []byte("client\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := WriteList(&buf, root); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "custom\nairvpn default\n" {
		t.Fatalf("%q", buf.String())
	}
}

func TestCryptoPickBounds(t *testing.T) {
	if _, err := CryptoPick(0); err == nil {
		t.Fatal("expected error")
	}
	n, err := CryptoPick(1)
	if err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	for i := 0; i < 8; i++ {
		n, err = CryptoPick(5)
		if err != nil || n < 0 || n >= 5 {
			t.Fatalf("%d %v", n, err)
		}
	}
}
