package pia

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetSignatureAndBind(t *testing.T) {
	sigBody, err := os.ReadFile("testdata/getSignature.json")
	if err != nil {
		t.Fatal(err)
	}
	bindBody, err := os.ReadFile("testdata/bindPort.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/getSignature":
			if r.URL.Query().Get("token") != "fixture-token" {
				t.Errorf("token query = %s", r.URL.Query().Get("token"))
			}
			_, _ = w.Write(sigBody)
		case "/bindPort":
			if r.URL.Query().Get("signature") != "test-signature" {
				t.Errorf("signature = %s", r.URL.Query().Get("signature"))
			}
			if r.URL.Query().Get("payload") == "" {
				t.Error("missing payload")
			}
			_, _ = w.Write(bindBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	sig, err := GetSignature(context.Background(), srv.Client(), srv.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	if sig.Port != 47047 || sig.Signature != "test-signature" {
		t.Fatalf("%+v", sig)
	}
	wantExp := time.Date(2026, 12, 30, 22, 33, 44, 114369906, time.UTC)
	if !sig.ExpiresAt.Equal(wantExp) {
		t.Fatal(sig.ExpiresAt)
	}
	if strings.Contains(sig.Payload, "fixture-token") {
		t.Fatal("payload should stay base64")
	}
	if err := BindPort(context.Background(), srv.Client(), srv.URL, sig.Payload, sig.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestGetSignatureRequiresExpiresAt(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte(`{"token":"fixture-token","port":47047,"created_at":"2024-01-01T00:00:00Z"}`))
	body, _ := json.Marshal(map[string]string{"status": "OK", "payload": raw, "signature": "sig"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	_, err := GetSignature(context.Background(), srv.Client(), srv.URL, "fixture-token")
	if err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "fixture-token") {
		t.Fatal(err)
	}
}

func TestGetSignatureRedactsToken(t *testing.T) {
	const token = "fixture-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"ERROR","message":"bad ` + token + `"}`))
	}))
	defer srv.Close()
	_, err := GetSignature(context.Background(), srv.Client(), srv.URL, token)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "ERROR") {
		t.Fatal(err)
	}
}

func TestGenerateToken(t *testing.T) {
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		_, _ = w.Write([]byte(`{"token":"generated-token"}`))
	}))
	defer srv.Close()
	got, err := GenerateToken(context.Background(), srv.Client(), srv.URL, "pia-user", "pia-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got != "generated-token" || user != "pia-user" || pass != "pia-pass" {
		t.Fatalf("token %q user %q", got, user)
	}
	if _, err := GenerateToken(context.Background(), srv.Client(), srv.URL, "", "x"); err == nil {
		t.Fatal("expected empty username to fail")
	}
}

func TestGatewayRejectsIPName(t *testing.T) {
	if _, err := GatewayClient("127.0.0.1", "127.0.0.1", "203.0.113.10", 1, nil); err == nil {
		t.Fatal("expected IP server name to fail")
	}
}

func TestGatewayDialsGateway(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
			close(got)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	client, err := GatewayClient("127.0.0.1", "127.0.0.1", "pf.example", port, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := client.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify")
	}
	if tr.TLSClientConfig.ServerName != "pf.example" || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("%+v", tr.TLSClientConfig)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://pf.example:19999/getSignature?token=fixture-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.Do(req)
	select {
	case <-got:
	default:
		t.Fatal("dial did not hit the gateway listener")
	}
}
