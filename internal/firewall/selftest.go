package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// SelfTest installs the kill switch in this network namespace and checks the tun rule.
// It is meant to run inside a container with CAP_NET_ADMIN.
func SelfTest() error {
	_, dev, err := ReadDefaultRoute4()
	if err != nil {
		return err
	}
	fw := Firewall{
		ExtIf:   dev,
		RPCPort: 9091,
		Endpoints: []Endpoint{{
			Addr:  "203.0.113.10",
			Proto: "udp",
			Port:  1194,
		}},
	}
	if err := fw.Install(); err != nil {
		return err
	}
	defer fw.Cleanup()
	if !has(fw.bin(), "OVPN_OUT", "-o", dev, "-d", "203.0.113.10", "-p", "udp", "--dport", "1194", "-j", "ACCEPT") {
		return fmt.Errorf("endpoint allow is missing")
	}
	if fw.HasTunAccept("tun0") {
		return fmt.Errorf("tun accept was installed before hook-up")
	}
	if err := proveDrop(fw.bin()); err != nil {
		return err
	}
	if err := fw.AllowTun("tun0", 51413); err != nil {
		return err
	}
	if !fw.HasTunAccept("tun0") {
		return fmt.Errorf("tun accept missing after hook-up")
	}
	if err := fw.RevokeTun("tun0", 51413); err != nil {
		return err
	}
	if fw.HasTunAccept("tun0") {
		return fmt.Errorf("tun accept remained after hook-down")
	}
	return nil
}

// proveDrop writes one UDP byte to an address reached only through the veth.
// The peer has no address, so the destination stays out of table local and the
// connected route on ovpnself is used. LOCAL_OUT runs before ARP, so the
// OVPN_OUT drop returns from Write.
func proveDrop(bin string) error {
	const srcDev, dstDev = "ovpnself", "ovpnpeer"
	const srcIP, dstIP = "192.0.2.1", "192.0.2.2"
	const dstPort = 9999
	if err := addVeth(srcDev, dstDev, srcIP); err != nil {
		return err
	}
	defer func() { _ = runIP("link", "del", srcDev) }()

	if err := sendUDP(srcIP, dstIP, dstPort); err == nil {
		return fmt.Errorf("udp send succeeded; OVPN_OUT did not drop %s", srcDev)
	}
	outRule := []string{"-o", srcDev, "-p", "udp", "--dport", strconv.Itoa(dstPort), "-j", "ACCEPT"}
	if err := insertRule(bin, "OVPN_OUT", outRule); err != nil {
		return err
	}
	if err := sendUDP(srcIP, dstIP, dstPort); err != nil {
		_ = deleteRule(bin, "OVPN_OUT", outRule...)
		return fmt.Errorf("udp send failed after accepting %s: %w", srcDev, err)
	}
	if err := deleteRule(bin, "OVPN_OUT", outRule...); err != nil {
		return err
	}
	if err := sendUDP(srcIP, dstIP, dstPort); err == nil {
		return fmt.Errorf("udp send succeeded after the %s accept was removed", srcDev)
	}
	return nil
}

func insertRule(bin, chain string, rule []string) error {
	return run(bin, append([]string{"-w", "-I", chain, "1"}, rule...)...)
}

func sendUDP(localIP, remote string, port int) error {
	conn, err := net.DialUDP("udp4",
		&net.UDPAddr{IP: net.ParseIP(localIP)},
		&net.UDPAddr{IP: net.ParseIP(remote), Port: port},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0})
	return err
}

func addVeth(srcDev, dstDev, srcIP string) error {
	_ = runIP("link", "del", srcDev)
	if err := runIP("link", "add", "name", srcDev, "type", "veth", "peer", "name", dstDev); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = runIP("link", "del", srcDev)
		}
	}()
	if err := runIP("addr", "add", srcIP+"/24", "dev", srcDev); err != nil {
		return err
	}
	if err := runIP("link", "set", srcDev, "up"); err != nil {
		return err
	}
	if err := runIP("link", "set", dstDev, "up"); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func runIP(args ...string) error {
	return runCmd(append([]string{"ip"}, args...)...)
}

func runCmd(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
