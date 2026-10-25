// Command ovpn-supervisor is PID 1 for the transmission-openvpn image.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lostinfuture/transmission-openvpn/internal/control"
	"github.com/lostinfuture/transmission-openvpn/internal/firewall"
	"github.com/lostinfuture/transmission-openvpn/internal/provider"
	"github.com/lostinfuture/transmission-openvpn/internal/supervisor"
)

var (
	version      = "dev"
	transmission = "4.1.4"
	openvpn      = "2.7.8"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "drop-exec" {
		if err := dropExec(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "drop-exec: %v\n", err)
			os.Exit(1)
		}
		return
	}
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "version":
		err = printVersions()
	case "run":
		err = supervisor.Run()
	case "hook-up":
		_, err = control.Call(control.SocketPath, control.HookUpFromEnv(os.Environ()))
	case "hook-down":
		_, err = control.Call(control.SocketPath, control.Down{
			Op:     "hook-down",
			Dev:    os.Getenv("dev"),
			Reason: "route-pre-down",
		})
	case "healthcheck":
		err = supervisor.Healthcheck()
	case "firewall-selftest":
		err = firewall.SelfTest()
	case "list-providers":
		err = provider.WriteList(os.Stdout, provider.BundledRoot)
	case "check-snapshot":
		err = provider.CheckSnapshot(provider.BundledRoot)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func printVersions() error {
	fmt.Printf("ovpn-supervisor %s\n", version)
	if err := requireVersion("transmission-daemon", []string{"--version"}, "transmission-daemon "+transmission); err != nil {
		return err
	}
	if err := requireVersion("openvpn", []string{"--version"}, "OpenVPN "+openvpn); err != nil {
		return err
	}
	if _, err := exec.LookPath("rustnet"); err != nil {
		fmt.Println("rustnet absent")
		return nil
	}
	return requireVersion("rustnet", []string{"--version"}, "1.7.0")
}

func requireVersion(bin string, args []string, needle string) error {
	c := exec.Command(bin, args...)
	out, err := c.CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return fmt.Errorf("%s: %w", bin, err)
	}
	if !strings.Contains(string(out), needle) {
		return fmt.Errorf("%s output %q does not contain %q", bin, strings.TrimSpace(string(out)), needle)
	}
	return nil
}
