package supervisor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	// healEvery matches the Docker HEALTHCHECK interval. Three dial failures are about 90s.
	healEvery = 30 * time.Second
	healDial  = 3 * time.Second
)

// healTick decides one watchdog sample.
// fails is the number of consecutive tun-bound dial failures already seen.
// A down tunnel resets that count and does not restart. A missing tun address
// restarts on this sample. An empty host is not dialed. The third dial failure
// restarts and resets the count.
func healTick(host string, tunUp, tunHasAddr, dialOK bool, fails int) (int, bool, string) {
	if !tunUp {
		return 0, false, ""
	}
	if !tunHasAddr {
		return 0, true, "tun address is missing"
	}
	if host == "" {
		return 0, false, ""
	}
	if dialOK {
		return 0, false, ""
	}
	fails++
	if fails >= 3 {
		return 0, true, "health dial failed three times"
	}
	return fails, false, ""
}

// dialTunHealth dials host:443 with the source address bound to the tun IP.
func dialTunHealth(local, host string) error {
	ip, err := netip.ParseAddr(local)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: healDial, LocalAddr: &net.TCPAddr{IP: ip.AsSlice()}}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return fmt.Errorf("health dial: %w", err)
	}
	conn.Close()
	return nil
}

// watchHealth samples the tun device. It does not count failures while the
// tunnel is down or while a restart is already in progress.
func (s *Sup) watchHealth(ctx context.Context, healCh chan<- string) {
	tick := time.NewTicker(healEvery)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.mu.Lock()
			if s.closed || s.healing {
				s.mu.Unlock()
				continue
			}
			up := s.tunnelUp
			local := s.local
			dev := s.devName
			host := s.cfg.HealthHost
			s.mu.Unlock()
			if !up {
				fails = 0
				continue
			}
			hasAddr := dev != "" && local != "" && addrOnDev(dev, local) == nil
			dialOK := false
			if hasAddr && host != "" {
				dialOK = dialTunHealth(local, host) == nil
			}
			next, restart, reason := healTick(host, true, hasAddr, dialOK, fails)
			fails = next
			if !restart {
				continue
			}
			select {
			case healCh <- reason:
			default:
			}
		}
	}
}
