package supervisor

import (
	"os"
	"strings"
	"testing"
)

func TestWriteResolvInPlace(t *testing.T) {
	path := t.TempDir() + "/resolv.conf"
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeResolv(path, []string{"10.8.0.1"}, []string{"example.net"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "nameserver 10.8.0.1\n") || strings.Contains(string(b), "127.0.0.11") {
		t.Fatalf("resolv = %q", b)
	}
	orig := []byte("nameserver 127.0.0.11\n")
	if err := os.WriteFile(path, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	// Restore uses the same truncate path the hook-down uses.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(orig); err != nil {
		t.Fatal(err)
	}
	f.Close()
}
