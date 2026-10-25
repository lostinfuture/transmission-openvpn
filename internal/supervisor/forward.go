package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lostinfuture/transmission-openvpn/internal/control"
	"github.com/lostinfuture/transmission-openvpn/internal/logx"
	"github.com/lostinfuture/transmission-openvpn/internal/portforward"
	"github.com/lostinfuture/transmission-openvpn/internal/provider/nordvpn"
	"github.com/lostinfuture/transmission-openvpn/internal/provider/pia"
	"github.com/lostinfuture/transmission-openvpn/internal/transmission"
)

const piaConfigPath = "/run/openvpn/pia.ovpn"
const nordConfigPath = "/run/openvpn/nordvpn.ovpn"

// forwardMode selects the port updater. piaOverride is true when PIA was asked to use NAT-PMP.
func forwardMode(provider, portForward string, disabled bool) (string, bool) {
	if disabled {
		return "", false
	}
	if portForward == "natpmp" {
		return "natpmp", provider == "pia"
	}
	switch provider {
	case "protonvpn":
		return "natpmp", false
	case "pia":
		return "pia", false
	default:
		return "", false
	}
}

func resolveNordVPN(ctx context.Context, cfg *Config) error {
	res, err := nordvpn.Fetch(ctx, nil, nordvpn.APIBase, nordvpn.CDNBase, nordvpn.Query{
		Country:  cfg.NordCountry,
		Protocol: cfg.NordProtocol,
		Category: cfg.NordCategory,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/run/openvpn", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(nordConfigPath, res.Body, 0o600); err != nil {
		return err
	}
	cfg.ConfigPath = nordConfigPath
	return nil
}

func resolvePIA(ctx context.Context, cfg *Config) error {
	if cfg.PIAToken != "" && cfg.Username == "" {
		cfg.Username, cfg.Password = pia.SplitToken(cfg.PIAToken)
	}
	regions, err := pia.FetchServers(ctx, nil, pia.ServerListURL)
	if err != nil {
		return err
	}
	region, err := pia.Select(regions, cfg.ConfigName)
	if err != nil {
		return err
	}
	if !region.PortForward {
		logx.Warn("provider", "pia region has no port forward; getSignature may fail", "region", region.ID)
	}
	if region.DNS == "" || net.ParseIP(region.DNS) != nil {
		logx.Warn("provider", "pia region has no dns name; port forwarding will not start", "region", region.ID)
	}
	if region.CN == "" {
		logx.Warn("provider", "pia region has no server cn; verify-x509-name is omitted", "region", region.ID)
	}
	text, err := pia.ConfigText(region, pia.CA())
	if err != nil {
		return err
	}
	if err := os.MkdirAll("/run/openvpn", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(piaConfigPath, []byte(text), 0o600); err != nil {
		return err
	}
	cfg.ConfigPath = piaConfigPath
	cfg.PFHostname = piaForwardName(region.CN, region.DNS)
	return nil
}

// piaForwardName is the TLS name for the port-forward gateway.
// The gateway certificate is the server CN. The regional DNS name is the fallback.
func piaForwardName(cn, dns string) string {
	if cn != "" && net.ParseIP(cn) == nil {
		return cn
	}
	return dns
}

func (s *Sup) startForward(up control.Up) {
	s.stopForward()
	mode, override := forwardMode(s.cfg.Provider, s.cfg.PortForward, s.cfg.DisablePF)
	if mode == "" {
		return
	}
	if override {
		logx.Info("supervisor", "PORT_FORWARD=natpmp selects NAT-PMP instead of the PIA signature loop")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.pfMu.Lock()
	s.pfCancel = cancel
	s.pfMu.Unlock()
	switch mode {
	case "pia":
		go s.runPIA(ctx, up)
	case "natpmp":
		go s.runNATPMP(ctx, up)
	}
}

func (s *Sup) stopForward() {
	s.pfMu.Lock()
	cancel := s.pfCancel
	s.pfCancel = nil
	s.pfMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Sup) runPIA(ctx context.Context, up control.Up) {
	local := up.IfconfigLocal
	gw := up.Gateway()
	if local == "" || gw == "" {
		logx.Error("supervisor", "pia port forward missing tun addresses")
		return
	}
	generated := false
	token := s.cfg.PIAToken
	var tokenClient *http.Client
	if token == "" && s.cfg.Username != "" && s.cfg.Password != "" {
		generated = true
		tokenClient = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
			},
		}
		got, err := pia.GenerateToken(ctx, tokenClient, "", s.cfg.Username, s.cfg.Password)
		if err != nil {
			tokenClient.CloseIdleConnections()
			logx.Error("supervisor", "pia token generation failed", "error", err.Error())
			return
		}
		token = got
		defer tokenClient.CloseIdleConnections()
	} else if token == "" && s.cfg.Username == "" {
		token = s.cfg.Password
	}
	if token == "" {
		logx.Error("supervisor", "pia port forward has no token")
		return
	}
	serverName := s.cfg.PFHostname
	if serverName == "" || net.ParseIP(serverName) != nil {
		serverName = firstNonIPRemote(s.cfg.ConfigPath)
	}
	if serverName == "" || net.ParseIP(serverName) != nil {
		logx.Error("supervisor", "pia port forward has no TLS hostname")
		return
	}
	roots, err := pia.CAPool()
	if err != nil {
		logx.Error("supervisor", "pia CA", "error", err.Error())
		return
	}
	client, err := pia.GatewayClient(local, gw, serverName, 0, roots)
	if err != nil {
		logx.Error("supervisor", "pia gateway client", "error", err.Error())
		return
	}
	defer client.CloseIdleConnections()
	base := "https://" + net.JoinHostPort(serverName, strconv.Itoa(pia.Port))
	var sig pia.Signature
	var have bool
	backoff := 15 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if !have || !time.Now().Before(sig.ExpiresAt) {
			got, err := pia.GetSignature(ctx, client, base, token)
			if err != nil {
				logx.Warn("supervisor", "pia getSignature failed", "error", err.Error())
				if generated {
					if fresh, gerr := pia.GenerateToken(ctx, tokenClient, "", s.cfg.Username, s.cfg.Password); gerr == nil {
						token = fresh
					}
				}
				if !sleepCtx(ctx, backoff) {
					return
				}
				if backoff < 5*time.Minute {
					backoff *= 2
					if backoff > 5*time.Minute {
						backoff = 5 * time.Minute
					}
				}
				continue
			}
			sig = got
			have = true
			backoff = 15 * time.Second
		}
		s.pfMu.Lock()
		cur := s.peerPort
		s.pfMu.Unlock()
		if cur != sig.Port {
			if err := s.applyPeerPort(ctx, up.Dev, sig.Port); err != nil {
				logx.Warn("supervisor", "peer port update failed", "error", err.Error())
			}
		}
		if err := pia.BindPort(ctx, client, base, sig.Payload, sig.Signature); err != nil {
			logx.Warn("supervisor", "pia bindPort failed", "error", err.Error())
		}
		wait, refresh := piaWait(sig.ExpiresAt, time.Now())
		if refresh {
			have = false
			if !sleepCtx(ctx, backoff) {
				return
			}
			continue
		}
		if !sleepCtx(ctx, wait) {
			return
		}
	}
}

// piaWait is the delay before the next bind. An expiry already in the past asks for a new signature
// instead of a zero sleep, which would tight-loop.
func piaWait(expires, now time.Time) (time.Duration, bool) {
	until := expires.Sub(now)
	if until <= 0 {
		return 0, true
	}
	if until < pia.BindEvery {
		return until, false
	}
	return pia.BindEvery, false
}

func (s *Sup) runNATPMP(ctx context.Context, up control.Up) {
	local := up.IfconfigLocal
	gw := up.Gateway()
	if local == "" || gw == "" {
		logx.Error("supervisor", "natpmp missing tun addresses")
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		s.pfMu.Lock()
		listen := s.peerPort
		s.pfMu.Unlock()
		ext, life, err := s.mapNATPMP(ctx, local, gw, up.Dev, listen)
		if err != nil {
			logx.Warn("supervisor", "natpmp failed", "error", err.Error())
			if !sleepCtx(ctx, portforward.RetryAfter(0)) {
				return
			}
			continue
		}
		if err := s.applyPeerPort(ctx, up.Dev, ext); err != nil {
			logx.Warn("supervisor", "peer port update failed", "error", err.Error())
			if !sleepCtx(ctx, portforward.RetryAfter(life)) {
				return
			}
			continue
		}
		if !sleepCtx(ctx, portforward.RefreshWait(life)) {
			return
		}
	}
}

func (s *Sup) mapNATPMP(ctx context.Context, local, gw, dev string, listen int) (int, uint32, error) {
	if listen < 1 || listen > 65535 {
		return 0, 0, fmt.Errorf("natpmp: listen port %d", listen)
	}
	n := listen
	var life uint32
	var announced int
	for attempt := 0; attempt < 2; attempt++ {
		tcp, err := portforward.Exchange(ctx, local, gw, 0, portforward.OpTCP, uint16(n), uint16(n), 3600)
		if err != nil {
			return 0, 0, err
		}
		if tcp.Lifetime == 0 || tcp.ExternalPort == 0 {
			return 0, 0, errors.New("natpmp: empty tcp map")
		}
		life = tcp.Lifetime
		plan := portforward.PlanTCP(attempt, n, int(tcp.ExternalPort))
		announced = plan.Announce
		if plan.Warn {
			logx.Warn("supervisor", "natpmp external port still differs from the listen port", "external", strconv.Itoa(plan.Announce), "listen", strconv.Itoa(n))
		}
		if !plan.Remap {
			break
		}
		if err := s.applyPeerPort(ctx, dev, plan.Announce); err != nil {
			return 0, 0, err
		}
		n = plan.Again
	}
	s.mapUDP(ctx, local, gw, announced)
	return announced, life, nil
}

func (s *Sup) mapUDP(ctx context.Context, local, gw string, want int) {
	internal := uint16(want)
	udp, err := portforward.Exchange(ctx, local, gw, 0, portforward.OpUDP, internal, internal, 3600)
	if err == nil && udp.Lifetime > 0 && int(udp.ExternalPort) == want {
		return
	}
	udp, err = portforward.Exchange(ctx, local, gw, 0, portforward.OpUDP, internal, internal, 3600)
	if err != nil || udp.Lifetime == 0 || int(udp.ExternalPort) != want {
		logx.Warn("supervisor", "natpmp udp external port differs from tcp; using the tcp port")
	}
}

func (s *Sup) applyPeerPort(ctx context.Context, dev string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("peer port %d", port)
	}
	if err := s.setPeerPort(ctx, port); err != nil {
		return err
	}
	s.pfMu.Lock()
	err := s.swapPeer(ctx, dev, port)
	s.pfMu.Unlock()
	if err != nil {
		return err
	}
	_ = s.writeStatus()
	return nil
}

// swapPeer holds pfMu. hook-down revokes under the same lock, so a late forwarder cannot reinstall allows.
func (s *Sup) swapPeer(ctx context.Context, dev string, port int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	up := s.tunnelUp && s.devName == dev
	s.mu.Unlock()
	if !up {
		return errors.New("tunnel down")
	}
	old := s.peerPort
	if s.cfg.Kill && old != port {
		if err := s.fw.ReplacePeer(dev, old, port); err != nil {
			return err
		}
	}
	if old != port {
		logx.Info("supervisor", "peer port updated", "port", strconv.Itoa(port))
	}
	s.peerPort = port
	return nil
}

func (s *Sup) setPeerPort(ctx context.Context, port int) error {
	c := &transmission.Client{
		URL:      "http://127.0.0.1:" + strconv.Itoa(s.rpcPort) + "/transmission/rpc",
		User:     s.cfg.RPCUser,
		Password: s.cfg.RPCPassword,
	}
	var last error
	for i := 0; i < 30; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = c.SetPeerPort(port)
		if last == nil {
			return nil
		}
		if strings.Contains(strings.ToLower(last.Error()), "unauthorized") {
			return last
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func firstNonIPRemote(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "remote" {
			continue
		}
		host := fields[1]
		if host != "" && net.ParseIP(host) == nil {
			return host
		}
	}
	return ""
}
