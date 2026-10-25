package firewall

import (
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

var defaultRouteRE = regexp.MustCompile(`default via (\S+) dev (\S+)`)
var inetRE = regexp.MustCompile(`inet (\S+)`)

// DefaultRoute4 parses `ip -4 route show default`.
func DefaultRoute4(text string) (gw netip.Addr, dev string, err error) {
	m := defaultRouteRE.FindStringSubmatch(text)
	if m == nil {
		return netip.Addr{}, "", fmt.Errorf("no ipv4 default route")
	}
	addr, err := netip.ParseAddr(m[1])
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("default gateway %q: %w", m[1], err)
	}
	if err := validateIf(m[2]); err != nil {
		return netip.Addr{}, "", err
	}
	return addr, m[2], nil
}

// FirstInetPrefix parses the first `inet addr/prefix` line and returns the masked network.
func FirstInetPrefix(text string) (netip.Prefix, error) {
	m := inetRE.FindStringSubmatch(text)
	if m == nil {
		return netip.Prefix{}, fmt.Errorf("no inet address")
	}
	p, err := netip.ParsePrefix(m[1])
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// ReadDefaultRoute4 runs ip.
func ReadDefaultRoute4() (netip.Addr, string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("ip route: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return DefaultRoute4(string(out))
}

// IfacePrefix4 returns the masked IPv4 network on dev.
func IfacePrefix4(dev string) (netip.Prefix, error) {
	if err := validateIf(dev); err != nil {
		return netip.Prefix{}, err
	}
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", dev).CombinedOutput()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("ip addr: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return FirstInetPrefix(string(out))
}

// ReplaceRoute installs `cidr via gw dev extif`.
func ReplaceRoute(cidr netip.Prefix, gw netip.Addr, extif string) error {
	if cidr.Bits() == 0 {
		return fmt.Errorf("refusing route %s", cidr)
	}
	out, err := exec.Command("ip", "route", "replace", cidr.String(), "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace %s: %w (%s)", cidr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DelDefault deletes the original default route.
func DelDefault(gw netip.Addr, extif string) error {
	out, err := exec.Command("ip", "route", "del", "default", "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route del default: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestoreDefault puts the original default route back.
func RestoreDefault(gw netip.Addr, extif string) error {
	out, err := exec.Command("ip", "route", "replace", "default", "via", gw.String(), "dev", extif).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace default: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
