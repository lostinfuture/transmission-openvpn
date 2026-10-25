package provider

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/lostinfuture/transmission-openvpn/internal/openvpn"
)

// CheckSnapshot fails when a provider directory has no config the sanitizer accepts.
// DNS is not used. The first file that sanitizes is enough.
func CheckSnapshot(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("openvpn snapshot %s: %w", root, err)
	}
	seen := 0
	var problems []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "custom" || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		seen++
		if err := checkProvider(filepath.Join(root, e.Name())); err != nil {
			problems = append(problems, e.Name()+": "+err.Error())
		}
	}
	if seen == 0 {
		return fmt.Errorf("openvpn snapshot %s has no providers", root)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}

func checkProvider(dir string) error {
	rels, err := walkConfigs(dir)
	if err != nil {
		return err
	}
	if len(rels) == 0 {
		return fmt.Errorf("no configs")
	}
	var ordered []string
	var rest []string
	for _, rel := range rels {
		if filepath.Base(rel) == "default.ovpn" {
			ordered = append(ordered, rel)
		} else {
			rest = append(rest, rel)
		}
	}
	ordered = append(ordered, rest...)
	var last error
	for _, rel := range ordered {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		p, err = followPointer(p)
		if err != nil {
			last = err
			continue
		}
		if _, err := openvpn.Prepare(p, nil, true, stubLookup, false); err != nil {
			last = err
			continue
		}
		return nil
	}
	return fmt.Errorf("every config failed (%d): %v", len(rels), last)
}

func stubLookup(string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}
