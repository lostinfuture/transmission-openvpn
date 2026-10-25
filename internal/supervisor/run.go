package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lostinfuture/transmission-openvpn/internal/control"
	"github.com/lostinfuture/transmission-openvpn/internal/firewall"
	"github.com/lostinfuture/transmission-openvpn/internal/logx"
	"github.com/lostinfuture/transmission-openvpn/internal/openvpn"
	"github.com/lostinfuture/transmission-openvpn/internal/provider"
	"github.com/lostinfuture/transmission-openvpn/internal/provider/pia"
	"github.com/lostinfuture/transmission-openvpn/internal/transmission"
)

const (
	resolvPath    = "/etc/resolv.conf"
	openvpnBin    = "/usr/bin/openvpn"
	transBin      = "/usr/bin/transmission-daemon"
	scriptKill    = 10 * time.Second
	transKill     = 8 * time.Second
	openvpnKill   = 5 * time.Second
	reassertEvery = 30 * time.Second
)

// Run is PID 1.
func Run() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	if cfg.RootWarned {
		logx.Warn("supervisor", "PUID=0 runs Transmission as root; the kill switch is best-effort")
	}
	if !cfg.Kill {
		logx.Warn("supervisor", "ENABLE_KILLSWITCH=false disables the egress drop")
	}
	if strings.EqualFold(os.Getenv("ENABLE_UFW"), "true") {
		logx.Info("supervisor", "UFW is not installed; the kill switch is already on")
	}
	if cfg.SelfHeal {
		logx.Info("supervisor", "SELFHEAL restarts OpenVPN after three tun health failures or a missing tun address")
	}
	if cfg.AllowUPnP {
		logx.Warn("supervisor", "ALLOW_UPNP=true lets Transmission map ports on the LAN")
	}
	if cfg.AllowScripts {
		logx.Warn("supervisor", "ALLOW_TORRENT_SCRIPTS=true lets RPC clients run scripts")
	}
	if !cfg.PeerDNS {
		logx.Warn("supervisor", "PEER_DNS=false leaves Docker DNS in resolv.conf")
	}
	if cfg.PFFromProvider {
		logx.Info("supervisor", "protonvpn sets PORT_FORWARD=natpmp")
	}
	for _, p := range cfg.Local {
		if p.Bits() < 16 {
			logx.Warn("supervisor", "LOCAL_NETWORK is wider than /16", "cidr", p.String())
		}
	}
	if err := loadCreds(&cfg); err != nil {
		return err
	}
	if cfg.Provider == "pia" && cfg.PIAToken != "" && cfg.Username == "" {
		cfg.Username, cfg.Password = pia.SplitToken(cfg.PIAToken)
	}
	if err := resolveConfig(&cfg); err != nil {
		return err
	}
	logx.Info("supervisor", "openvpn config", "provider", cfg.Provider, "config", cfg.ConfigPath)
	if _, err := os.Stat(cfg.ConfigPath); err != nil {
		return fmt.Errorf("openvpn config %s: %w", cfg.ConfigPath, err)
	}
	s := &Sup{cfg: cfg}
	s.cond = sync.NewCond(&s.mu)
	res, err := openvpn.Prepare(cfg.ConfigPath, cfg.Opts, cfg.Username != "", s.lookup, cfg.IPv6)
	if err != nil {
		return err
	}
	if cfg.Username == "" && res.User != "" {
		cfg.Username, cfg.Password = res.User, res.Password
		s.cfg = cfg
	}
	for _, key := range res.Stripped {
		logx.Info("openvpn", "stripped directive", "directive", key)
	}
	if err := os.MkdirAll("/run/openvpn", 0o700); err != nil {
		return err
	}
	if cfg.Username != "" {
		body := cfg.Username + "\n" + cfg.Password + "\n"
		if err := os.WriteFile("/run/openvpn/auth", []byte(body), 0o600); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/run/openvpn/config.ovpn", []byte(res.Config), 0o600); err != nil {
		return err
	}
	dump, err := transmission.DumpSettings(transBin)
	if err != nil {
		return err
	}
	user, err := readUserSettings(filepath.Join(cfg.Home, "settings.json"))
	if err != nil {
		return err
	}
	s.dump, s.env = dump, os.Environ()
	s.user = user
	merged, err := s.merge("")
	if err != nil {
		return err
	}
	s.rpcPort = transmission.Int(merged, "rpc_port", 9091)
	s.peerPort = transmission.Int(merged, "peer_port", 51413)
	if err := os.MkdirAll(cfg.Home, 0o755); err != nil {
		return err
	}
	for _, dir := range []string{"/data/completed", "/data/incomplete", "/data/watch"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := s.ownFiles(); err != nil {
		return err
	}
	if err := ensureTun(cfg.CreateTun); err != nil {
		return err
	}
	gw, extif, err := firewall.ReadDefaultRoute4()
	if err != nil {
		return err
	}
	s.gw, s.extif = gw, extif
	locals := append([]netip.Prefix{}, cfg.Local...)
	if cfg.AllowGWNet {
		p, err := firewall.IfacePrefix4(extif)
		if err != nil {
			return err
		}
		locals = append(locals, p)
		logx.Info("supervisor", "allowing the original gateway network", "cidr", p.String())
	}
	s.locals = locals
	eps := make([]firewall.Endpoint, len(res.Endpoints))
	for i, ep := range res.Endpoints {
		eps[i] = firewall.Endpoint{Addr: ep.Addr, Proto: ep.Proto, Port: ep.Port}
	}
	s.fw = firewall.Firewall{
		ExtIf: extif, RPCPort: s.rpcPort, Local: locals, ExtraTCP: cfg.ExtraTCP,
		Endpoints: eps, IPv6: cfg.IPv6,
	}
	if cfg.Kill {
		if err := s.fw.Install(); err != nil {
			return err
		}
		logx.Info("firewall", "kill switch installed", "extif", extif, "rpc_port", strconv.Itoa(s.rpcPort))
	}
	for _, p := range locals {
		if err := firewall.ReplaceRoute(p, gw, extif); err != nil {
			return err
		}
	}
	if err := s.runScript(context.Background(), "/scripts/openvpn-pre-start.sh", scriptArgs("", "", "", "", "", "init")); err != nil {
		return err
	}
	if err := os.MkdirAll("/run/ovpn-supervisor", 0o700); err != nil {
		return err
	}
	_ = os.Remove(control.SocketPath)
	ln, err := net.Listen("unix", control.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(control.SocketPath, 0o600); err != nil {
		return err
	}
	s.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 2)
		signalNotify(sig)
		<-sig
		logx.Info("supervisor", "received stop signal")
		cancel()
	}()
	go func() {
		err := control.Serve(ln, s.handle)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logx.Error("supervisor", "control socket closed", "error", err.Error())
		}
	}()
	if err := s.writeStatus(); err != nil {
		return err
	}
	// After the kill switch, before OpenVPN, so the capture sees eth0.
	s.startRustnet(ctx)
	s.ovpnArgs = append([]string{"--config", "/run/openvpn/config.ovpn"}, s.cfg.Opts...)
	if s.cfg.DCO == "off" {
		s.ovpnArgs = append(s.ovpnArgs, "--disable-dco")
	}
	waitCh, done, err := s.spawnOpenVPN()
	if err != nil {
		return err
	}
	var healCh chan string
	if s.cfg.SelfHeal {
		healCh = make(chan string, 1)
		go s.watchHealth(ctx, healCh)
	}
	for {
		select {
		case <-ctx.Done():
			return s.stopOpenVPN(ln, waitCh)
		case err := <-waitCh:
			s.mu.Lock()
			closed := s.closed
			healing := s.healing
			s.mu.Unlock()
			if ctx.Err() != nil || closed {
				_ = ln.Close()
				s.hookMu.Lock()
				s.stopForward()
				s.hookMu.Unlock()
				s.stopTM()
				return nil
			}
			if healing {
				waitCh, done, err = s.afterHealExit()
				if err != nil {
					return err
				}
				select {
				case <-healCh:
				default:
				}
				continue
			}
			_ = ln.Close()
			s.hookMu.Lock()
			s.stopForward()
			s.hookMu.Unlock()
			s.stopTM()
			if err != nil {
				return fmt.Errorf("openvpn exited: %w", err)
			}
			return errors.New("openvpn exited")
		case reason := <-healCh:
			s.beginHeal(reason, done)
		}
	}
}

// spawnOpenVPN starts OpenVPN on the config already written to /run/openvpn/config.ovpn.
// A SELFHEAL restart calls this again. It does not resolve remotes, run the pre-start
// script, or install the kill switch a second time.
func (s *Sup) spawnOpenVPN() (<-chan error, <-chan struct{}, error) {
	cmd := exec.Command(openvpnBin, s.ovpnArgs...)
	cmd.Env = childEnv(os.Environ())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	s.ovpn = cmd
	s.mu.Unlock()
	go s.pump(stdout, "openvpn", cmd)
	go s.pump(stderr, "openvpn", cmd)
	logx.Info("supervisor", "openvpn started", "pid", strconv.Itoa(cmd.Process.Pid))
	waitCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		err := cmd.Wait()
		close(done)
		waitCh <- err
	}()
	return waitCh, done, nil
}

// afterHealExit runs only after the OpenVPN process that beginHeal signaled has exited.
// hook-down normally clears the tunnel. If it is still up, onDown stops Transmission.
// The replacement process is not followed by startTM; the next hook-up does that.
func (s *Sup) afterHealExit() (<-chan error, <-chan struct{}, error) {
	s.hookMu.Lock()
	s.mu.Lock()
	up := s.tunnelUp
	dev := s.devName
	s.mu.Unlock()
	if up {
		_ = s.onDown(control.Down{Dev: dev, Reason: "selfheal"})
	}
	s.hookMu.Unlock()
	waitCh, done, err := s.spawnOpenVPN()
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	s.healing = false
	s.mu.Unlock()
	return waitCh, done, nil
}

// beginHeal signals one OpenVPN process. The SIGKILL is armed on that process
// and is skipped once its Wait returns, so a replacement process is left alone.
func (s *Sup) beginHeal(reason string, done <-chan struct{}) {
	s.mu.Lock()
	if s.closed || s.healing || s.ovpn == nil || s.ovpn.Process == nil {
		s.mu.Unlock()
		return
	}
	s.healing = true
	proc := s.ovpn.Process
	s.mu.Unlock()
	logx.Info("supervisor", "restarting openvpn", "reason", reason)
	_ = proc.Signal(syscall.SIGTERM)
	go func() {
		timer := time.NewTimer(openvpnKill)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			select {
			case <-done:
			default:
				_ = proc.Kill()
			}
		}
	}()
}

func (s *Sup) stopOpenVPN(ln net.Listener, waitCh <-chan error) error {
	s.mu.Lock()
	s.closed = true
	cmd := s.ovpn
	s.mu.Unlock()
	s.stopTM()
	s.hookMu.Lock()
	s.stopForward()
	s.hookMu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitCh:
		case <-time.After(openvpnKill):
			_ = cmd.Process.Kill()
			<-waitCh
		}
	}
	_ = ln.Close()
	s.mu.Lock()
	wasUp := s.tunnelUp
	dev := s.devName
	s.mu.Unlock()
	if wasUp {
		s.hookMu.Lock()
		_ = s.onDown(control.Down{Dev: dev, Reason: "shutdown"})
		s.hookMu.Unlock()
	}
	return nil
}

// Sup is the running supervisor.
type Sup struct {
	cfg      Config
	dump     map[string]any
	user     map[string]any
	env      []string
	fw       firewall.Firewall
	gw       netip.Addr
	extif    string
	locals   []netip.Prefix
	rpcPort  int
	peerPort int
	ln       net.Listener

	mu         sync.Mutex
	hookMu     sync.Mutex
	tmMu       sync.Mutex
	pfMu       sync.Mutex
	pfCancel   context.CancelFunc
	cond       *sync.Cond
	closed     bool
	ovpn       *exec.Cmd
	ovpnArgs   []string
	healing    bool
	tm         *exec.Cmd
	tmCancel   context.CancelFunc
	tmExited   chan struct{}
	starting   bool
	stopWait   chan struct{}
	tunnelUp   bool
	tunGen     uint64
	devName    string
	local      string
	gateway    string
	tunAccept  bool
	dco        bool
	resolvOrig []byte
	resolvOn   bool
	droppedDef bool
	reasserted map[string]time.Time
}

func (s *Sup) lookup(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (s *Sup) merge(tunIP string) (map[string]any, error) {
	return transmission.Merge(s.dump, s.user, s.env, transmission.Options{
		AllowUPnP: s.cfg.AllowUPnP, AllowScripts: s.cfg.AllowScripts,
		RPCUser: s.cfg.RPCUser, RPCPassword: s.cfg.RPCPassword, TunIPv4: tunIP,
	})
}

func (s *Sup) handle(req []byte) control.Reply {
	// One hook at a time. route-up and route-pre-down both touch resolv.conf and the tun rules.
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	var head struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(req, &head); err != nil {
		return control.Reply{Error: err.Error()}
	}
	switch head.Op {
	case "hook-up":
		var up control.Up
		if err := json.Unmarshal(req, &up); err != nil {
			return control.Reply{Error: err.Error()}
		}
		if err := s.onUp(up); err != nil {
			logx.Error("supervisor", "hook-up failed", "error", err.Error())
			return control.Reply{Error: err.Error()}
		}
		return control.Reply{OK: true}
	case "hook-down":
		var down control.Down
		if err := json.Unmarshal(req, &down); err != nil {
			return control.Reply{Error: err.Error()}
		}
		if err := s.onDown(down); err != nil {
			logx.Error("supervisor", "hook-down failed", "error", err.Error())
			return control.Reply{Error: err.Error()}
		}
		return control.Reply{OK: true}
	default:
		return control.Reply{Error: "unknown op"}
	}
}

func (s *Sup) onUp(up control.Up) error {
	if err := checkDev(up.Dev); err != nil {
		return err
	}
	if up.IfconfigLocal == "" {
		return errors.New("hook-up missing ifconfig_local")
	}
	if s.cfg.Kill {
		s.pfMu.Lock()
		peer := s.peerPort
		s.pfMu.Unlock()
		if err := s.fw.AllowTun(up.Dev, peer); err != nil {
			return err
		}
	}
	if s.cfg.PeerDNS && len(up.DNS) > 0 {
		if s.resolvOrig == nil {
			b, err := os.ReadFile(resolvPath)
			if err != nil {
				return err
			}
			s.resolvOrig = b
		}
		if err := writeResolv(resolvPath, up.DNS, up.Search); err != nil {
			return err
		}
		s.resolvOn = true
	} else if s.cfg.PeerDNS {
		logx.Warn("supervisor", "peer sent no DNS; resolv.conf was left unchanged")
	}
	for _, p := range s.locals {
		if err := firewall.ReplaceRoute(p, s.gw, s.extif); err != nil {
			return err
		}
	}
	if s.cfg.DropDefault && !s.droppedDef {
		if err := firewall.DelDefault(s.gw, s.extif); err != nil {
			logx.Warn("supervisor", "could not drop the original default route", "error", err.Error())
		} else {
			s.droppedDef = true
		}
	}
	s.mu.Lock()
	s.tunGen++
	gen := s.tunGen
	s.tunnelUp = true
	s.devName = up.Dev
	s.local = up.IfconfigLocal
	s.gateway = up.Gateway()
	s.tunAccept = s.cfg.Kill
	s.mu.Unlock()
	_ = s.writeStatus()
	logx.Info("supervisor", "tunnel up", "dev", up.Dev, "addr", up.IfconfigLocal, "gateway", up.Gateway())
	go s.kickTM(up, gen)
	s.startForward(up)
	return nil
}

func (s *Sup) onDown(down control.Down) error {
	// Bump the generation before stopTM so a queued kickTM cannot start Transmission on the way down.
	s.mu.Lock()
	s.tunGen++
	s.tunnelUp = false
	s.tunAccept = false
	s.mu.Unlock()
	s.stopForward()
	s.stopTM()
	if s.resolvOn && s.resolvOrig != nil {
		f, err := os.OpenFile(resolvPath, os.O_WRONLY|os.O_TRUNC, 0o644)
		if err == nil {
			_, werr := f.Write(s.resolvOrig)
			_ = f.Close()
			if werr != nil {
				logx.Warn("supervisor", "resolv.conf restore failed", "error", werr.Error())
			}
		}
		s.resolvOn = false
	}
	if s.droppedDef {
		if err := firewall.RestoreDefault(s.gw, s.extif); err != nil {
			logx.Warn("supervisor", "default route restore failed", "error", err.Error())
		}
		s.droppedDef = false
	}
	dev := down.Dev
	if dev == "" {
		dev = s.dev()
	}
	if s.cfg.Kill && dev != "" {
		s.pfMu.Lock()
		_ = s.fw.RevokeTun(dev, s.peerPort)
		s.pfMu.Unlock()
	}
	_ = s.writeStatus()
	logx.Info("supervisor", "tunnel down", "dev", dev)
	return nil
}

func (s *Sup) kickTM(up control.Up, gen uint64) {
	s.tmMu.Lock()
	defer s.tmMu.Unlock()
	s.mu.Lock()
	if s.closed || s.tunGen != gen {
		s.mu.Unlock()
		return
	}
	same := (s.tm != nil || s.starting) && s.local == up.IfconfigLocal && s.devName == up.Dev
	running := s.tm != nil || s.starting
	s.mu.Unlock()
	if same {
		return
	}
	if running {
		logx.Info("supervisor", "restarting transmission for the new tun address")
		s.stopTM()
	}
	s.mu.Lock()
	closed := s.closed
	stale := s.tunGen != gen || !s.tunnelUp || s.local != up.IfconfigLocal || s.devName != up.Dev
	s.mu.Unlock()
	if closed || stale {
		return
	}
	s.startTM(up, gen)
}

func (s *Sup) startTM(up control.Up, gen uint64) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.starting = true
	s.tmCancel = cancel
	s.cond.Broadcast()
	s.mu.Unlock()
	finish := func() {
		s.mu.Lock()
		s.starting = false
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	args := scriptArgs(up.Dev, up.TunMTU, up.LinkMTU, up.IfconfigLocal, up.IfconfigRemote, up.ScriptContext)
	if err := s.runScript(ctx, "/scripts/transmission-pre-start.sh", args); err != nil {
		logx.Error("supervisor", "pre-start script failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	merged, err := s.merge(up.IfconfigLocal)
	if err != nil {
		logx.Error("supervisor", "settings merge failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	if err := writeSettings(filepath.Join(s.cfg.Home, "settings.json"), merged, s.cfg.PUID, s.cfg.PGID); err != nil {
		logx.Error("supervisor", "settings write failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	s.pfMu.Lock()
	peer := s.peerPort
	s.pfMu.Unlock()
	targs := []string{
		"--foreground",
		"--config-dir", s.cfg.Home,
		"--bind-address-ipv4", up.IfconfigLocal,
		"--rpc-bind-address", "0.0.0.0",
		"--port", strconv.Itoa(s.rpcPort),
		"--peerport", strconv.Itoa(peer),
		"--no-lpd",
	}
	if !s.cfg.AllowUPnP {
		targs = append(targs, "--no-portmap")
	}
	if !s.cfg.LogStdout {
		targs = append(targs, "--logfile", filepath.Join(s.cfg.Home, "transmission.log"))
	}
	var cmd *exec.Cmd
	if s.cfg.PUID == 0 {
		cmd = exec.Command(transBin, targs...)
		cmd.Env = s.transmissionEnv()
	} else {
		self, err := os.Executable()
		if err != nil {
			self = "/usr/bin/ovpn-supervisor"
		}
		argv := []string{"drop-exec", "--uid", strconv.Itoa(s.cfg.PUID), "--gid", strconv.Itoa(s.cfg.PGID), "--nofile", strconv.Itoa(s.cfg.OpenFiles), "--", transBin}
		argv = append(argv, targs...)
		cmd = exec.Command(self, argv...)
		cmd.Env = s.transmissionEnv()
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.Error("supervisor", "transmission pipe", "error", err.Error())
		cancel()
		finish()
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		logx.Error("supervisor", "transmission pipe", "error", err.Error())
		cancel()
		finish()
		return
	}
	s.mu.Lock()
	if s.closed || !s.tunnelUp || s.tunGen != gen {
		s.mu.Unlock()
		cancel()
		finish()
		return
	}
	s.mu.Unlock()
	if err := cmd.Start(); err != nil {
		logx.Error("supervisor", "transmission start failed", "error", err.Error())
		cancel()
		finish()
		return
	}
	exited := make(chan struct{})
	s.mu.Lock()
	if s.closed || ctx.Err() != nil || !s.tunnelUp || s.tunGen != gen {
		s.starting = false
		s.cond.Broadcast()
		s.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()
		return
	}
	s.tm = cmd
	s.tmExited = exited
	s.starting = false
	s.cond.Broadcast()
	s.mu.Unlock()
	go s.pump(stdout, "transmission", nil)
	go s.pump(stderr, "transmission", nil)
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	logx.Info("supervisor", "transmission started", "pid", strconv.Itoa(cmd.Process.Pid), "bind", up.IfconfigLocal)
	_ = s.writeStatus()
	if err := waitRPC(ctx, s.rpcPort); err != nil {
		logx.Error("supervisor", "transmission rpc did not come up", "error", err.Error())
		s.stopTM()
		return
	}
	if err := s.runScript(ctx, "/scripts/transmission-post-start.sh", args); err != nil {
		logx.Warn("supervisor", "post-start script failed", "error", err.Error())
	}
	go s.reassert(ctx)
}

func (s *Sup) stopTM() {
	s.mu.Lock()
	if s.stopWait != nil {
		ch := s.stopWait
		s.mu.Unlock()
		<-ch
		return
	}
	ch := make(chan struct{})
	s.stopWait = ch
	if s.tmCancel != nil {
		s.tmCancel()
	}
	for s.starting {
		s.cond.Wait()
	}
	cmd := s.tm
	exited := s.tmExited
	dev := s.devName
	local := s.local
	s.mu.Unlock()

	args := scriptArgs(dev, "", "", local, "", "restart")
	_ = s.runScript(context.Background(), "/scripts/transmission-pre-stop.sh", args)
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if exited != nil {
			select {
			case <-exited:
			case <-time.After(transKill):
				_ = cmd.Process.Kill()
				<-exited
			}
		}
	}
	_ = s.runScript(context.Background(), "/scripts/transmission-post-stop.sh", args)
	s.mu.Lock()
	s.tm = nil
	s.tmCancel = nil
	s.tmExited = nil
	if s.stopWait == ch {
		s.stopWait = nil
	}
	s.mu.Unlock()
	close(ch)
	_ = s.writeStatus()
}

func (s *Sup) reassert(ctx context.Context) {
	if s.cfg.AllowScripts {
		return
	}
	if !s.canReassert() {
		logx.Warn("supervisor", "RPC authentication is required and TRANSMISSION_RPC_PASSWORD is unset; a hashed settings password cannot be sent")
		return
	}
	c := &transmission.Client{
		URL:      "http://127.0.0.1:" + strconv.Itoa(s.rpcPort) + "/transmission/rpc",
		User:     s.cfg.RPCUser,
		Password: s.cfg.RPCPassword,
	}
	tick := time.NewTicker(reassertEvery)
	defer tick.Stop()
	s.correctScripts(c)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.correctScripts(c)
		}
	}
}

func (s *Sup) canReassert() bool {
	merged, err := s.merge("")
	if err != nil {
		return false
	}
	auth, _ := merged["rpc_authentication_required"].(bool)
	pass, _ := merged["rpc_password"].(string)
	if !rpcAuthUsable(auth, pass, s.cfg.RPCPassword) {
		return false
	}
	return true
}

// rpcAuthUsable reports whether this process can call RPC.
// When auth is on, only TRANSMISSION_RPC_PASSWORD is sent. A settings value that
// starts with "{" is Transmission's stored hash. Either way, an empty env password fails fast.
func rpcAuthUsable(auth bool, filePass, envPass string) bool {
	if !auth {
		return true
	}
	if envPass != "" {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(filePass), "{") {
		return false
	}
	return false
}

func (s *Sup) correctScripts(c *transmission.Client) {
	got, err := c.SessionGet()
	if err != nil {
		logx.Warn("supervisor", "session_get failed", "error", err.Error())
		return
	}
	keys := []string{"script_torrent_done_enabled", "script_torrent_done_seeding_enabled", "script_torrent_added_enabled"}
	dirty := false
	for _, key := range keys {
		if b, ok := got[key].(bool); ok && b {
			dirty = true
			s.mu.Lock()
			if s.reasserted == nil {
				s.reasserted = map[string]time.Time{}
			}
			last := s.reasserted[key]
			if time.Since(last) > time.Minute {
				s.reasserted[key] = time.Now()
				s.mu.Unlock()
				logx.Warn("supervisor", "turning torrent script back off", "key", key)
			} else {
				s.mu.Unlock()
			}
		}
	}
	if dirty {
		if err := c.SetScriptsDisabled(); err != nil {
			logx.Warn("supervisor", "session_set failed", "error", err.Error())
		}
	}
}

func (s *Sup) pump(r io.Reader, component string, own *exec.Cmd) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		line = redactSecret(line, s.cfg.Password)
		line = redactSecret(line, s.cfg.PIAToken)
		if component == "rustnet" {
			logx.ChildRaw(component, line)
		} else {
			logx.Child(component, line)
		}
		if component != "openvpn" {
			continue
		}
		low := strings.ToLower(line)
		s.mu.Lock()
		if strings.Contains(line, "DCO device") && strings.Contains(low, "opened") {
			s.dco = true
		}
		if strings.Contains(low, "disabling data channel offload") {
			s.dco = false
		}
		need := s.cfg.DCO == "on" && strings.Contains(line, "Initialization Sequence Completed") && !s.dco
		target := own
		if target == nil {
			target = s.ovpn
		}
		s.mu.Unlock()
		if need && target != nil && target.Process != nil {
			logx.Error("supervisor", "OPENVPN_DCO=on but data channel offload is not active")
			_ = target.Process.Signal(syscall.SIGTERM)
		}
		_ = s.writeStatus()
	}
	if err := sc.Err(); err != nil {
		logx.Warn(component, "log line too long", "error", err.Error())
		_, _ = io.Copy(io.Discard, r)
	}
}

func (s *Sup) writeStatus() error {
	s.pfMu.Lock()
	peer := s.peerPort
	s.pfMu.Unlock()
	s.mu.Lock()
	st := status{
		Dev: s.devName, TunIPv4: s.local, VPNGateway: s.gateway, Provider: s.cfg.Provider,
		DCO: s.dco, RPCPort: s.rpcPort, PeerPort: peer, TunEgressAccept: s.tunAccept,
		TunnelUp: s.tunnelUp, KillSwitch: s.cfg.Kill, HealthHost: s.cfg.HealthHost,
	}
	if s.tm != nil && s.tm.Process != nil {
		st.TransmissionPID = s.tm.Process.Pid
	}
	s.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/run/ovpn-supervisor", 0o700); err != nil {
		return err
	}
	tmp := control.StatusPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, control.StatusPath)
}

func (s *Sup) dev() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devName
}

type status struct {
	Dev             string `json:"dev"`
	TunIPv4         string `json:"tun_ipv4"`
	VPNGateway      string `json:"vpn_gateway,omitempty"`
	Provider        string `json:"provider"`
	DCO             bool   `json:"dco"`
	TransmissionPID int    `json:"transmission_pid"`
	RPCPort         int    `json:"rpc_port"`
	PeerPort        int    `json:"peer_port"`
	TunEgressAccept bool   `json:"tun_egress_accept"`
	TunnelUp        bool   `json:"tunnel_up"`
	KillSwitch      bool   `json:"kill_switch"`
	HealthHost      string `json:"health_host,omitempty"`
}

func (s *Sup) runScript(ctx context.Context, path string, args []string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := scriptDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s: %w", filepath.Dir(path), err)
	}
	if err := scriptFile(st); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cctx, cancel := context.WithTimeout(ctx, scriptKill)
	defer cancel()
	bin := path
	argv := args
	if st.Mode()&0o111 == 0 {
		bin = "/bin/sh"
		argv = append([]string{path}, args...)
	}
	cmd := exec.CommandContext(cctx, bin, argv...)
	cmd.Env = childEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line != "" {
			line = redactSecret(line, s.cfg.Password)
			line = redactSecret(line, s.cfg.PIAToken)
			logx.Child("script", line)
		}
	}
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func (s *Sup) ownFiles() error {
	uid, gid := s.cfg.PUID, s.cfg.PGID
	if err := chownTree(s.cfg.Home, uid, gid); err != nil {
		return err
	}
	if s.cfg.ApplyPerms {
		if err := chownTree("/data", uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

func scriptDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if !st.IsDir() {
		return errors.New("not a directory")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return errors.New("not owned by root")
	}
	if st.Mode()&0o022 != 0 {
		return errors.New("writable by group or other")
	}
	return nil
}

func scriptFile(st os.FileInfo) error {
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a file")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return errors.New("not owned by root")
	}
	if st.Mode()&0o022 != 0 {
		return errors.New("writable by group or other")
	}
	return nil
}

func writeSettings(path string, m map[string]any, uid, gid int) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	okWrite := false
	defer func() {
		if !okWrite {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	okWrite = true
	return nil
}

func readUserSettings(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		bad := path + ".bad"
		_ = os.Rename(path, bad)
		logx.Warn("supervisor", "settings.json is not a JSON object; starting from defaults", "saved", bad)
		return map[string]any{}, nil
	}
	return m, nil
}

func loadCreds(cfg *Config) error {
	if cfg.Username != "" {
		return nil
	}
	for _, path := range []string{"/run/secrets/openvpn_creds", "/config/openvpn-credentials.txt"} {
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		var lines []string
		for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			if strings.TrimSpace(ln) != "" {
				lines = append(lines, strings.TrimSpace(ln))
			}
		}
		if len(lines) < 2 {
			return fmt.Errorf("%s needs a username line and a password line", path)
		}
		cfg.Username, cfg.Password = lines[0], lines[1]
		return nil
	}
	return nil
}

// mkdev is glibc's makedev(3). syscall.Mkdev is not in every Alpine Go.
// major 10 minor 200 is /dev/net/tun.
func mkdev(major, minor uint32) uint64 {
	return (uint64(major&0xfffff000) << 32) | (uint64(major&0xfff) << 8) |
		(uint64(minor&0xffffff00) << 12) | uint64(minor&0xff)
}

func ensureTun(create bool) error {
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return nil
	}
	if !create {
		return errors.New("/dev/net/tun is missing; pass --device /dev/net/tun")
	}
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return err
	}
	err := syscall.Mknod("/dev/net/tun", syscall.S_IFCHR|0o600, int(mkdev(10, 200)))
	if err != nil {
		return fmt.Errorf("create /dev/net/tun: %w", err)
	}
	return nil
}

func waitRPC(ctx context.Context, port int) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out dialing %s", addr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func scriptArgs(dev, tunMTU, linkMTU, local, remote, ctx string) []string {
	return []string{dev, tunMTU, linkMTU, local, remote, ctx}
}

func checkDev(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("bad tun device %q", name)
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return fmt.Errorf("bad tun device %q", name)
		}
	}
	return nil
}

func resolveConfig(cfg *Config) error {
	if cfg.Provider == "custom" {
		return nil
	}
	if cfg.Provider == "nordvpn" || cfg.Provider == "pia" {
		if cfg.Source == "bundled" || cfg.Source == "github" {
			logx.Info("provider", "using the API; this provider is not in the snapshot", "provider", cfg.Provider, "source", cfg.Source)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if cfg.Provider == "nordvpn" {
			return resolveNordVPN(ctx, cfg)
		}
		return resolvePIA(ctx, cfg)
	}
	root := provider.BundledRoot
	if cfg.Source == "github" {
		if err := provider.FetchGitHub(context.Background(), nil, cfg.GitHubRepo, cfg.GitHubRev, provider.FetchRoot); err != nil {
			return err
		}
		root = provider.FetchRoot
	}
	path, err := provider.Resolve(root, cfg.Provider, cfg.ConfigName, nil)
	if err != nil {
		return err
	}
	cfg.ConfigPath = path
	return nil
}

func (s *Sup) transmissionEnv() []string {
	env := childEnv(os.Environ())
	if s.cfg.WebHome != "" {
		env = append(env, "TRANSMISSION_WEB_HOME="+s.cfg.WebHome)
	}
	return env
}

func redactSecret(line, secret string) string {
	if len(secret) < 3 {
		return line
	}
	return strings.ReplaceAll(line, secret, "[redacted]")
}

func childEnv(env []string) []string {
	var out []string
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		lk := strings.ToLower(k)
		if strings.Contains(lk, "pass") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") || strings.Contains(lk, "credential") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func signalNotify(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
}

// Healthcheck is the Docker HEALTHCHECK.
func Healthcheck() error {
	b, err := os.ReadFile(control.StatusPath)
	if err != nil {
		return fmt.Errorf("no status: %w", err)
	}
	var st status
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if !st.TunnelUp || st.Dev == "" || st.TunIPv4 == "" {
		return errors.New("tunnel is down")
	}
	if err := addrOnDev(st.Dev, st.TunIPv4); err != nil {
		return err
	}
	if st.KillSwitch {
		fw := firewall.Firewall{}
		if !fw.HasTunAccept(st.Dev) {
			return errors.New("tun egress accept is missing")
		}
	}
	url := "http://127.0.0.1:" + strconv.Itoa(st.RPCPort) + "/transmission/web/"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case 200, 401, 409:
	default:
		return fmt.Errorf("rpc http %d", resp.StatusCode)
	}
	if st.HealthHost != "" {
		if err := dialTunHealth(st.TunIPv4, st.HealthHost); err != nil {
			return err
		}
	}
	return nil
}

func addrOnDev(dev, want string) error {
	out, err := exec.Command("ip", "-4", "addr", "show", "dev", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr %s: %w", dev, err)
	}
	text := string(out)
	if !strings.Contains(text, want+"/") && !strings.Contains(text, " "+want+" ") && !strings.Contains(text, " "+want+"\n") {
		return fmt.Errorf("%s has no address %s", dev, want)
	}
	return nil
}
