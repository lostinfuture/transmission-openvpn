package portforward

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestExchange(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			errCh <- err
			return
		}
		if n != 12 || buf[0] != 0 || buf[1] != OpTCP {
			errCh <- errUnexpected(n, buf[1])
			return
		}
		internal := binary.BigEndian.Uint16(buf[4:6])
		suggested := binary.BigEndian.Uint16(buf[6:8])
		life := binary.BigEndian.Uint32(buf[8:12])
		if internal != 51413 || suggested != 51413 || life != 3600 {
			errCh <- errUnexpected(int(internal), buf[1])
			return
		}
		var resp [16]byte
		resp[1] = OpTCP | 0x80
		binary.BigEndian.PutUint16(resp[8:10], internal)
		binary.BigEndian.PutUint16(resp[10:12], 47047)
		binary.BigEndian.PutUint32(resp[12:16], 3600)
		_, err = pc.WriteToUDP(resp[:], addr)
		errCh <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := Exchange(ctx, "127.0.0.1", "127.0.0.1", pc.LocalAddr().(*net.UDPAddr).Port, OpTCP, 51413, 51413, 3600)
	if serveErr := <-errCh; serveErr != nil && err == nil {
		t.Fatal(serveErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.ExternalPort != 47047 || res.Lifetime != 3600 || res.ResultCode != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestExchangeRetransmits(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			errCh <- err
			return
		}
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			errCh <- err
			return
		}
		if n != 12 || buf[1] != OpUDP {
			errCh <- errUnexpected(n, buf[1])
			return
		}
		var resp [16]byte
		resp[1] = OpUDP | 0x80
		binary.BigEndian.PutUint16(resp[8:10], 1)
		binary.BigEndian.PutUint16(resp[10:12], 9)
		binary.BigEndian.PutUint32(resp[12:16], 60)
		_, err = pc.WriteToUDP(resp[:], addr)
		errCh <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Exchange(ctx, "127.0.0.1", "127.0.0.1", pc.LocalAddr().(*net.UDPAddr).Port, OpUDP, 1, 1, 60)
	if serveErr := <-errCh; serveErr != nil && err == nil {
		t.Fatal(serveErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if res.ExternalPort != 9 || res.Lifetime != 60 {
		t.Fatalf("%+v", res)
	}
}

func TestExchangeResultCode(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 32)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var resp [16]byte
		resp[1] = OpUDP | 0x80
		binary.BigEndian.PutUint16(resp[2:4], 3)
		_, _ = pc.WriteToUDP(resp[:], addr)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = Exchange(ctx, "127.0.0.1", "127.0.0.1", pc.LocalAddr().(*net.UDPAddr).Port, OpUDP, 1, 1, 60)
	if err == nil {
		t.Fatal("expected result code")
	}
}

func TestRefreshAndPlan(t *testing.T) {
	if RefreshWait(3600) != 1800*time.Second {
		t.Fatal(RefreshWait(3600))
	}
	if RefreshWait(1) != time.Second {
		t.Fatal(RefreshWait(1))
	}
	if RefreshWait(0) != 30*time.Second {
		t.Fatal(RefreshWait(0))
	}
	if RetryAfter(3600) != 30*time.Second || RetryAfter(60) != 15*time.Second || RetryAfter(0) != 30*time.Second {
		t.Fatalf("%s %s %s", RetryAfter(3600), RetryAfter(60), RetryAfter(0))
	}
	same := PlanTCP(0, 51413, 51413)
	if same.Remap || same.Warn || same.Announce != 51413 {
		t.Fatalf("%+v", same)
	}
	move := PlanTCP(0, 51413, 47047)
	if !move.Remap || move.Warn || move.Again != 47047 || move.Announce != 47047 {
		t.Fatalf("%+v", move)
	}
	stuck := PlanTCP(1, 47047, 40000)
	if stuck.Remap || !stuck.Warn || stuck.Announce != 40000 {
		t.Fatalf("%+v", stuck)
	}
}

type unexpected struct{ n, op int }

func errUnexpected(n int, op byte) error { return unexpected{n, int(op)} }

func (e unexpected) Error() string { return "unexpected natpmp request" }
