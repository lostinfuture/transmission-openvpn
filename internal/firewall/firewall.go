// Package firewall installs the container kill switch.
package firewall

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// Endpoint is one handshake allow on the external interface.
type Endpoint struct {
	Addr  string
	Proto string
	Port  int
}

// Firewall is the iptables policy for one container network namespace.
type Firewall struct {
	Bin       string
	Bin6      string
	ExtIf     string
	RPCPort   int
	Local     []netip.Prefix
	ExtraTCP  []int
	Endpoints []Endpoint
	IPv6      bool
}

func (f Firewall) bin() string {
	if f.Bin != "" {
		return f.Bin
	}
	return "iptables"
}

func (f Firewall) bin6() string {
	if f.Bin6 != "" {
		return f.Bin6
	}
	return "ip6tables"
}

// Install sets the pre-tunnel policy. Tun egress is not accepted yet.
func (f Firewall) Install() error {
	if err := validateIf(f.ExtIf); err != nil {
		return err
	}
	if err := f.install4(); err != nil {
		return err
	}
	if err := f.install6(); err != nil {
		return err
	}
	return nil
}

func (f Firewall) install4() error {
	b := f.bin()
	if err := run(b, "-w", "-N", "OVPN_OUT"); err != nil {
		return fmt.Errorf("iptables -N OVPN_OUT: %w", err)
	}
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, ep := range f.Endpoints {
		if strings.Contains(ep.Addr, ":") {
			continue
		}
		rules = append(rules, []string{"-o", f.ExtIf, "-d", ep.Addr, "-p", ep.Proto, "--dport", strconv.Itoa(ep.Port), "-j", "ACCEPT"})
	}
	for _, p := range f.Local {
		if !p.Addr().Is4() {
			continue
		}
		rules = append(rules, []string{"-o", f.ExtIf, "-d", p.String(), "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-j", "DROP"})
	for _, rule := range rules {
		args := append([]string{"-w", "-A", "OVPN_OUT"}, rule...)
		if err := run(b, args...); err != nil {
			return err
		}
	}
	if err := run(b, "-w", "-I", "OUTPUT", "1", "-j", "OVPN_OUT"); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-F", "INPUT"); err != nil {
		return err
	}
	in := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "icmp", "--icmp-type", "3", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "ACCEPT"},
		{"-i", "tun+", "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "DROP"},
	}
	for _, port := range f.ExtraTCP {
		in = append(in, []string{"-i", f.ExtIf, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
	}
	in = append(in, []string{"-i", "tun+", "-j", "DROP"})
	for _, rule := range in {
		args := append([]string{"-w", "-A", "INPUT"}, rule...)
		if err := run(b, args...); err != nil {
			return err
		}
	}
	return nil
}

func (f Firewall) install6() error {
	b := f.bin6()
	if !f.IPv6 {
		if err := run(b, "-w", "-P", "INPUT", "DROP"); err != nil {
			if ipv6Disabled(err) {
				return nil
			}
			return fmt.Errorf("ip6tables policy: %w", err)
		}
		if err := run(b, "-w", "-P", "OUTPUT", "DROP"); err != nil {
			if ipv6Disabled(err) {
				return nil
			}
			return fmt.Errorf("ip6tables policy: %w", err)
		}
		_ = insertOnce(b, "INPUT", "-i", "lo", "-j", "ACCEPT")
		_ = insertOnce(b, "OUTPUT", "-o", "lo", "-j", "ACCEPT")
		return nil
	}
	if err := run(b, "-w", "-N", "OVPN_OUT"); err != nil {
		return err
	}
	rules := [][]string{
		{"-o", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, ep := range f.Endpoints {
		if !strings.Contains(ep.Addr, ":") {
			continue
		}
		rules = append(rules, []string{"-o", f.ExtIf, "-d", ep.Addr, "-p", ep.Proto, "--dport", strconv.Itoa(ep.Port), "-j", "ACCEPT"})
	}
	for _, p := range f.Local {
		if !p.Addr().Is6() {
			continue
		}
		rules = append(rules, []string{"-o", f.ExtIf, "-d", p.String(), "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-j", "DROP"})
	for _, rule := range rules {
		if err := run(b, append([]string{"-w", "-A", "OVPN_OUT"}, rule...)...); err != nil {
			return err
		}
	}
	if err := run(b, "-w", "-I", "OUTPUT", "1", "-j", "OVPN_OUT"); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-P", "OUTPUT", "DROP"); err != nil {
		return err
	}
	if err := run(b, "-w", "-F", "INPUT"); err != nil {
		return err
	}
	in := [][]string{
		{"-i", "lo", "-j", "ACCEPT"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"},
		{"-i", f.ExtIf, "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "ACCEPT"},
		{"-i", "tun+", "-p", "tcp", "--dport", strconv.Itoa(f.RPCPort), "-j", "DROP"},
		{"-i", "tun+", "-j", "DROP"},
	}
	for _, rule := range in {
		if err := run(b, append([]string{"-w", "-A", "INPUT"}, rule...)...); err != nil {
			return err
		}
	}
	return nil
}

// AllowTun inserts the tun egress accept and the peer-port input allows.
func (f Firewall) AllowTun(dev string, peerPort int) error {
	if err := validateIf(dev); err != nil {
		return err
	}
	if err := f.allowFam(f.bin(), dev, peerPort); err != nil {
		return err
	}
	if f.IPv6 {
		return f.allowFam(f.bin6(), dev, peerPort)
	}
	return nil
}

func (f Firewall) allowFam(bin, dev string, peerPort int) error {
	chain := "OVPN_OUT"
	if err := insertOnce(bin, chain, "-o", dev, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := insertOnce(bin, "INPUT", "-i", dev, "-p", "udp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT"); err != nil {
		return err
	}
	return insertOnce(bin, "INPUT", "-i", dev, "-p", "tcp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT")
}

// ReplacePeer swaps the INPUT peer-port allows. Equal ports are a no-op.
// The tun egress accept is left in place.
func (f Firewall) ReplacePeer(dev string, oldPort, newPort int) error {
	if oldPort == newPort {
		return nil
	}
	if err := validateIf(dev); err != nil {
		return err
	}
	if err := replacePeerFam(f.bin(), dev, oldPort, newPort); err != nil {
		return err
	}
	if f.IPv6 {
		return replacePeerFam(f.bin6(), dev, oldPort, newPort)
	}
	return nil
}

func replacePeerFam(bin, dev string, oldPort, newPort int) error {
	_ = deleteRule(bin, "INPUT", "-i", dev, "-p", "udp", "--dport", strconv.Itoa(oldPort), "-j", "ACCEPT")
	_ = deleteRule(bin, "INPUT", "-i", dev, "-p", "tcp", "--dport", strconv.Itoa(oldPort), "-j", "ACCEPT")
	if err := insertOnce(bin, "INPUT", "-i", dev, "-p", "udp", "--dport", strconv.Itoa(newPort), "-j", "ACCEPT"); err != nil {
		return err
	}
	return insertOnce(bin, "INPUT", "-i", dev, "-p", "tcp", "--dport", strconv.Itoa(newPort), "-j", "ACCEPT")
}

// RevokeTun removes the rules AllowTun inserted.
func (f Firewall) RevokeTun(dev string, peerPort int) error {
	if err := validateIf(dev); err != nil {
		return err
	}
	_ = deleteRule(f.bin(), "OVPN_OUT", "-o", dev, "-j", "ACCEPT")
	_ = deleteRule(f.bin(), "INPUT", "-i", dev, "-p", "udp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT")
	_ = deleteRule(f.bin(), "INPUT", "-i", dev, "-p", "tcp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT")
	if f.IPv6 {
		_ = deleteRule(f.bin6(), "OVPN_OUT", "-o", dev, "-j", "ACCEPT")
		_ = deleteRule(f.bin6(), "INPUT", "-i", dev, "-p", "udp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT")
		_ = deleteRule(f.bin6(), "INPUT", "-i", dev, "-p", "tcp", "--dport", strconv.Itoa(peerPort), "-j", "ACCEPT")
	}
	return nil
}

// HasTunAccept reports whether the tun egress accept is installed.
func (f Firewall) HasTunAccept(dev string) bool {
	return has(f.bin(), "OVPN_OUT", "-o", dev, "-j", "ACCEPT")
}

// Cleanup removes the chains this process installed and restores ACCEPT policies.
func (f Firewall) Cleanup() {
	b := f.bin()
	_ = run(b, "-w", "-D", "OUTPUT", "-j", "OVPN_OUT")
	_ = run(b, "-w", "-F", "OVPN_OUT")
	_ = run(b, "-w", "-X", "OVPN_OUT")
	_ = run(b, "-w", "-P", "INPUT", "ACCEPT")
	_ = run(b, "-w", "-F", "INPUT")
	b6 := f.bin6()
	_ = run(b6, "-w", "-D", "OUTPUT", "-j", "OVPN_OUT")
	_ = run(b6, "-w", "-F", "OVPN_OUT")
	_ = run(b6, "-w", "-X", "OVPN_OUT")
	_ = run(b6, "-w", "-P", "INPUT", "ACCEPT")
	_ = run(b6, "-w", "-P", "OUTPUT", "ACCEPT")
	_ = run(b6, "-w", "-F", "INPUT")
	_ = run(b6, "-w", "-F", "OUTPUT")
}

func insertOnce(bin, chain string, rule ...string) error {
	if has(bin, chain, rule...) {
		return nil
	}
	args := append([]string{"-w", "-I", chain, "1"}, rule...)
	return run(bin, args...)
}

func deleteRule(bin, chain string, rule ...string) error {
	if !has(bin, chain, rule...) {
		return nil
	}
	return run(bin, append([]string{"-w", "-D", chain}, rule...)...)
}

func has(bin, chain string, rule ...string) bool {
	return run(bin, append([]string{"-w", "-C", chain}, rule...)...) == nil
}

func run(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipv6Disabled(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "protocol not supported") || strings.Contains(msg, "address family not supported") || strings.Contains(msg, "can't initialize")
}

func validateIf(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("bad interface %q", name)
	}
	for _, r := range name {
		if r == '+' && name == "tun+" {
			return nil
		}
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return fmt.Errorf("bad interface %q", name)
		}
	}
	return nil
}
