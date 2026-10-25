package pia

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Port is the gateway HTTPS port. Tests may dial another port; production stays here.
	Port = 19999
	// TokenURL issues a port-forward token from the account username and password.
	TokenURL = "https://www.privateinternetaccess.com/gtoken/generateToken"
	// BindEvery is how often the same payload is refreshed. The gateway drops the port if bind stops.
	BindEvery = 15 * time.Minute
	maxJSON   = 8 << 20
)

// Signature is one getSignature result. Payload is the original base64 string reused by bindPort.
// The decoded token is not retained.
type Signature struct {
	Payload   string
	Signature string
	Port      int
	ExpiresAt time.Time
}

// GetSignature calls getSignature once per signature lifetime.
// Errors include status and message only. The token is redacted.
func GetSignature(ctx context.Context, client *http.Client, baseURL, token string) (Signature, error) {
	if token == "" {
		return Signature{}, fmt.Errorf("pia: empty token")
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + "/getSignature")
	if err != nil {
		return Signature{}, err
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	body, err := getLimited(ctx, httpClient(client), u.String(), maxJSON, token)
	if err != nil {
		return Signature{}, err
	}
	var resp struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Signature{}, redactErr(fmt.Errorf("pia: bad json"), token)
	}
	if resp.Status != "OK" {
		return Signature{}, statusErr(resp.Status, resp.Message, token)
	}
	port, exp, err := parsePayload(resp.Payload)
	if err != nil {
		return Signature{}, redactErr(err, token)
	}
	if resp.Signature == "" {
		return Signature{}, fmt.Errorf("pia: missing signature")
	}
	return Signature{Payload: resp.Payload, Signature: resp.Signature, Port: port, ExpiresAt: exp}, nil
}

// BindPort refreshes the same payload and signature.
func BindPort(ctx context.Context, client *http.Client, baseURL, payload, signature string) error {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + "/bindPort")
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("payload", payload)
	q.Set("signature", signature)
	u.RawQuery = q.Encode()
	body, err := getLimited(ctx, httpClient(client), u.String(), maxJSON, payload, signature)
	if err != nil {
		return err
	}
	var resp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return redactErr(fmt.Errorf("pia: bad json"), payload, signature)
	}
	if resp.Status != "OK" {
		return statusErr(resp.Status, resp.Message, payload, signature)
	}
	return nil
}

// GatewayClient dials gateway:port from local and verifies TLS as serverName.
// The URL host is the PF hostname. TCP does not follow that host, so the request cannot leave via extif.
// InsecureSkipVerify is not a mode. roots nil uses the process roots; production passes CAPool.
func GatewayClient(local, gateway, serverName string, port int, roots *x509.CertPool) (*http.Client, error) {
	if port == 0 {
		port = Port
	}
	lip := net.ParseIP(local)
	if lip == nil {
		return nil, fmt.Errorf("pia: bad local address %q", local)
	}
	if net.ParseIP(gateway) == nil {
		return nil, fmt.Errorf("pia: bad gateway %q", gateway)
	}
	if serverName == "" || net.ParseIP(serverName) != nil {
		return nil, fmt.Errorf("pia: port-forward server name must be a hostname")
	}
	d := &net.Dialer{Timeout: 20 * time.Second, LocalAddr: &net.TCPAddr{IP: lip}}
	target := net.JoinHostPort(gateway, strconv.Itoa(port))
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", target)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
		// The gateway is a small HTTPS service. Stay on HTTP/1.1.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}, nil
}

// GenerateToken requests a port-forward token with HTTP basic auth.
// The account password is not the token. Errors do not include the password or the token.
func GenerateToken(ctx context.Context, client *http.Client, tokenURL, user, pass string) (string, error) {
	if user == "" || pass == "" {
		return "", fmt.Errorf("pia: token generation needs a username and password")
	}
	if tokenURL == "" {
		tokenURL = TokenURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(user, pass)
	c := client
	if c == nil {
		c = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
			},
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", redactErr(err, user, pass)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON+1))
	if err != nil {
		return "", redactErr(err, user, pass)
	}
	if int64(len(body)) > maxJSON {
		return "", fmt.Errorf("pia: token response exceeds %d bytes", maxJSON)
	}
	if resp.StatusCode != http.StatusOK {
		return "", redactErr(fmt.Errorf("pia: token status %d", resp.StatusCode), user, pass)
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", redactErr(fmt.Errorf("pia: token json"), user, pass)
	}
	if parsed.Token == "" {
		return "", fmt.Errorf("pia: empty generated token")
	}
	return parsed.Token, nil
}

func parsePayload(raw string) (int, time.Time, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("pia: payload: %w", err)
	}
	var body struct {
		Port      int    `json:"port"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(decoded, &body); err != nil {
		return 0, time.Time{}, fmt.Errorf("pia: payload: %w", err)
	}
	if body.ExpiresAt == "" {
		return 0, time.Time{}, fmt.Errorf("pia: payload missing expires_at")
	}
	exp, err := time.Parse(time.RFC3339Nano, body.ExpiresAt)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("pia: expires_at: %w", err)
	}
	if body.Port < 1 || body.Port > 65535 {
		return 0, time.Time{}, fmt.Errorf("pia: payload port %d", body.Port)
	}
	return body.Port, exp, nil
}

func statusErr(status, message string, secrets ...string) error {
	if status == "" {
		status = "unknown"
	}
	msg := "pia: status " + status
	if message != "" {
		msg += ": " + message
	}
	return redactErr(errors.New(msg), secrets...)
}

func redactErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, secret, "[redacted]")
		msg = strings.ReplaceAll(msg, url.QueryEscape(secret), "[redacted]")
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func getLimited(ctx context.Context, client *http.Client, rawURL string, limit int64, secrets ...string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, redactErr(err, secrets...)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactErr(err, secrets...)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, redactErr(err, secrets...)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("pia: response exceeds %d bytes", limit)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("pia: response exceeds %d bytes", limit)
	}
	if resp.StatusCode != http.StatusOK {
		var meta struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &meta) == nil && (meta.Status != "" || meta.Message != "") {
			return nil, statusErr(meta.Status, meta.Message, secrets...)
		}
		return nil, fmt.Errorf("pia: http %d", resp.StatusCode)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, fmt.Errorf("pia: empty response")
	}
	return b, nil
}
