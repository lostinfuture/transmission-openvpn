// Package provider resolves the OpenVPN config for this image.
package provider

import (
	"fmt"
	"path/filepath"
	"strings"
)

// CustomPath returns /etc/openvpn/custom/<name>.ovpn. An empty name selects default.ovpn.
func CustomPath(name string) (string, error) {
	if name == "" {
		name = "default"
	}
	if name != filepath.Base(name) || strings.Contains(name, "..") || strings.ContainsAny(name, `/\,`) {
		return "", fmt.Errorf("invalid OPENVPN_CONFIG %q", name)
	}
	return filepath.Join("/etc/openvpn/custom", name+".ovpn"), nil
}
