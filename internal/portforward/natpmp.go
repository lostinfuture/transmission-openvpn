// Package portforward maps a port on the tun gateway with NAT-PMP (RFC 6886).
package portforward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	// Port is the NAT-PMP UDP port.
	Port = 5351
	// OpUDP maps a UDP port.
	OpUDP byte = 1
	// OpTCP maps a TCP port.
	OpTCP byte = 2
)

// Result is one mapping response. A non-zero ResultCode is an error from Exchange.
type Result struct {
	Opcode       byte
	ResultCode   uint16
	Epoch        uint32
	InternalPort uint16
	ExternalPort uint16
	Lifetime     uint32
}

// Exchange sends one map request to gatewayPort (5351 when 0) from local.
func Exchange(ctx context.Context, local, gateway string, gatewayPort int, opcode byte, internal, suggested uint16, lifetime uint32) (Result, error) {
	if gatewayPort == 0 {
		gatewayPort = Port
	}
	lip := net.ParseIP(local)
	gip := net.ParseIP(gateway)
	if lip == nil || gip == nil {
		return Result{}, fmt.Errorf("natpmp: bad address")
	}
	var d net.Dialer
	d.LocalAddr = &net.UDPAddr{IP: lip}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(gateway, fmt.Sprintf("%d", gatewayPort)))
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	var req [12]byte
	req[1] = opcode
	binary.BigEndian.PutUint16(req[4:6], internal)
	binary.BigEndian.PutUint16(req[6:8], suggested)
	binary.BigEndian.PutUint32(req[8:12], lifetime)
	// RFC 6886 retransmit: 250ms, then double, through 8s. Stop early on the context deadline.
	waits := []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
	}
	var buf [16]byte
	for _, wait := range waits {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if dl, ok := ctx.Deadline(); ok {
			if remain := time.Until(dl); remain < wait {
				wait = remain
			}
		}
		if wait <= 0 {
			break
		}
		if _, err := conn.Write(req[:]); err != nil {
			return Result{}, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			return Result{}, err
		}
		n, err := conn.Read(buf[:])
		if err != nil {
			if timeout(err) {
				continue
			}
			return Result{}, err
		}
		return parseMap(buf[:n], opcode)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{}, fmt.Errorf("natpmp: no response")
}

func timeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func parseMap(buf []byte, opcode byte) (Result, error) {
	if len(buf) != 16 {
		return Result{}, fmt.Errorf("natpmp: short response (%d)", len(buf))
	}
	if buf[0] != 0 {
		return Result{}, fmt.Errorf("natpmp: version %d", buf[0])
	}
	if buf[1] != opcode|0x80 {
		return Result{}, fmt.Errorf("natpmp: opcode %d", buf[1])
	}
	res := Result{
		Opcode:       buf[1],
		ResultCode:   binary.BigEndian.Uint16(buf[2:4]),
		Epoch:        binary.BigEndian.Uint32(buf[4:8]),
		InternalPort: binary.BigEndian.Uint16(buf[8:10]),
		ExternalPort: binary.BigEndian.Uint16(buf[10:12]),
		Lifetime:     binary.BigEndian.Uint32(buf[12:16]),
	}
	if res.ResultCode != 0 {
		return res, fmt.Errorf("natpmp: result %d", res.ResultCode)
	}
	return res, nil
}

// RefreshWait is half the mapping lifetime, and at least one second.
// A zero lifetime is a deleted map; the caller waits 30 seconds and tries again.
func RefreshWait(lifetime uint32) time.Duration {
	if lifetime == 0 {
		return 30 * time.Second
	}
	sec := time.Duration(lifetime) / 2
	if sec < 1 {
		sec = 1
	}
	return sec * time.Second
}

// RetryAfter is the pause after a failed refresh: the shorter of 30s and lifetime/4.
// A zero lifetime waits 30 seconds.
func RetryAfter(lifetime uint32) time.Duration {
	if lifetime == 0 {
		return 30 * time.Second
	}
	quarter := time.Duration(lifetime) * time.Second / 4
	if quarter <= 0 || quarter > 30*time.Second {
		return 30 * time.Second
	}
	return quarter
}

// TCPPlan is one step of aligning Transmission's listen port with the mapped port.
type TCPPlan struct {
	Announce int
	Remap    bool
	Warn     bool
	Again    int
}

// PlanTCP caps a listen-port remap at two attempts.
// When the external port differs, the caller session-sets Announce and requests again with internal = external.
func PlanTCP(attempt, listen, external int) TCPPlan {
	if external == listen {
		return TCPPlan{Announce: listen}
	}
	if attempt >= 1 {
		return TCPPlan{Announce: external, Warn: true}
	}
	return TCPPlan{Announce: external, Remap: true, Again: external}
}
