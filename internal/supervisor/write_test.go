package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSettingsReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeSettings(link, map[string]any{"download_dir": "/data/completed"}, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "keep" {
		t.Fatalf("target = %q %v", body, err)
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		t.Fatalf("settings.json mode %v", st.Mode())
	}
}

func TestScriptDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := scriptDir(file); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linkdir")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := scriptDir(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	err := scriptDir(dir)
	if os.Geteuid() != 0 {
		if err == nil || !strings.Contains(err.Error(), "root") {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err = scriptDir(dir)
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatal(err)
	}
}

func TestScriptFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := scriptFile(st); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose.sh")
	if err := os.WriteFile(loose, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	st, err = os.Lstat(loose)
	if err != nil {
		t.Fatal(err)
	}
	err = scriptFile(st)
	if err == nil {
		t.Fatal("expected loose hook to fail")
	}
	if os.Geteuid() == 0 && !strings.Contains(err.Error(), "writable") {
		t.Fatal(err)
	}
}
