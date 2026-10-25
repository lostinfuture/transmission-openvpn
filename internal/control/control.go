// Package control is the newline-delimited JSON socket between OpenVPN hooks and PID 1.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// SocketPath is the root-only control socket.
	SocketPath = "/run/ovpn-supervisor/control.sock"
	// StatusPath is the root-only healthcheck state file.
	StatusPath = "/run/ovpn-supervisor/status.json"
	maxMessage = 64 << 10
)

// Up is the hook-up request. RouteVPNGateway is the tun gateway on topology subnet.
type Up struct {
	Op                string   `json:"op"`
	Dev               string   `json:"dev"`
	IfconfigLocal     string   `json:"ifconfig_local"`
	IfconfigRemote    string   `json:"ifconfig_remote"`
	IfconfigNetmask   string   `json:"ifconfig_netmask"`
	IfconfigIPv6Local string   `json:"ifconfig_ipv6_local"`
	RouteVPNGateway   string   `json:"route_vpn_gateway"`
	Proto             string   `json:"proto"`
	TrustedIP         string   `json:"trusted_ip,omitempty"`
	TrustedPort       int      `json:"trusted_port,omitempty"`
	RedirectGateway   bool     `json:"redirect_gateway"`
	DNS               []string `json:"dns"`
	Search            []string `json:"search,omitempty"`
	TunMTU            string   `json:"tun_mtu,omitempty"`
	LinkMTU           string   `json:"link_mtu,omitempty"`
	ScriptContext     string   `json:"script_context,omitempty"`
}

// Down is the hook-down request.
type Down struct {
	Op     string `json:"op"`
	Dev    string `json:"dev"`
	Reason string `json:"reason"`
}

// Reply is the single response on a connection.
type Reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Gateway returns the tun gateway. topology subnet fills route_vpn_gateway and leaves ifconfig_remote empty.
func (u Up) Gateway() string {
	if u.RouteVPNGateway != "" {
		return u.RouteVPNGateway
	}
	return u.IfconfigRemote
}

// Serve reads one request per connection and writes one reply.
func Serve(ln net.Listener, handle func([]byte) Reply) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(45 * time.Second))
			req, err := readMsg(c)
			rep := Reply{OK: false, Error: "read"}
			if err == nil {
				rep = handle(req)
			} else {
				rep.Error = err.Error()
			}
			_ = writeMsg(c, rep)
		}(conn)
	}
}

// Call dials the socket and returns the reply. A reply of ok:false is an error.
func Call(sock string, req any) (Reply, error) {
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err := writeMsg(conn, req); err != nil {
		return Reply{}, err
	}
	body, err := readMsg(conn)
	if err != nil {
		return Reply{}, err
	}
	var rep Reply
	if err := json.Unmarshal(body, &rep); err != nil {
		return Reply{}, err
	}
	if !rep.OK {
		if rep.Error == "" {
			rep.Error = "not ok"
		}
		return rep, errors.New(rep.Error)
	}
	return rep, nil
}

func readMsg(r io.Reader) ([]byte, error) {
	br := bufio.NewReaderSize(r, maxMessage+1)
	line, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull || len(line) > maxMessage {
		return nil, fmt.Errorf("control message exceeds %d bytes", maxMessage)
	}
	if len(line) == 0 && err != nil {
		return nil, err
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return nil, errors.New("control message is not newline-terminated")
	}
	out := make([]byte, len(line)-1)
	copy(out, line)
	return out, nil
}

func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return fmt.Errorf("control message exceeds %d bytes", maxMessage)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
