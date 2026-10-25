// Package nordvpn fetches one OpenVPN config from the public NordVPN directory.
// Directory calls are unauthenticated. There is no API token.
package nordvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// APIBase is the countries and recommendations directory.
	APIBase = "https://api.nordvpn.com/v1"
	// CDNBase is the prefix for ovpn_udp and ovpn_tcp config files.
	CDNBase = "https://downloads.nordcdn.com/configs/files"
	maxJSON = 8 << 20
	maxOVPN = 1 << 20
)

// Query is one recommendation. Country is an ISO code. Empty Country omits the country filter.
// Protocol is udp or tcp. Category is passed through as a servers group identifier.
type Query struct {
	Country  string
	Protocol string
	Category string
}

// Result is the chosen hostname and the downloaded config body.
type Result struct {
	Hostname  string
	Body      []byte
	ConfigURL string
}

// ConfigURL is the ovpn download for one hostname.
func ConfigURL(cdnBase, protocol, hostname string) (string, error) {
	if !validHostname(hostname) {
		return "", fmt.Errorf("nordvpn: bad hostname %q", hostname)
	}
	dir, ext, err := protoFiles(protocol)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(cdnBase, "/")
	return base + "/" + dir + "/servers/" + hostname + "." + ext + ".ovpn", nil
}

// RecommendationURL is the recommendations request. haveCountry false omits filters[country_id].
func RecommendationURL(apiBase string, countryID int, haveCountry bool, protocol, category string) (string, error) {
	tech, err := techName(protocol)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimRight(apiBase, "/") + "/servers/recommendations")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("limit", "1")
	if haveCountry {
		q.Set("filters[country_id]", strconv.Itoa(countryID))
	}
	q.Set("filters[servers_technologies][identifier]", tech)
	if category != "" {
		q.Set("filters[servers_groups][identifier]", category)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Fetch resolves one server and downloads its .ovpn. A non-200 or an empty body is an error.
// client may be nil. apiBase and cdnBase default to the production constants when empty.
func Fetch(ctx context.Context, client *http.Client, apiBase, cdnBase string, q Query) (Result, error) {
	if apiBase == "" {
		apiBase = APIBase
	}
	if cdnBase == "" {
		cdnBase = CDNBase
	}
	client = httpClient(client)
	var countryID int
	haveCountry := strings.TrimSpace(q.Country) != ""
	if haveCountry {
		id, err := countryIDByCode(ctx, client, apiBase, q.Country)
		if err != nil {
			return Result{}, err
		}
		countryID = id
	}
	recURL, err := RecommendationURL(apiBase, countryID, haveCountry, q.Protocol, q.Category)
	if err != nil {
		return Result{}, err
	}
	var recs []struct {
		Hostname string `json:"hostname"`
	}
	if err := getJSON(ctx, client, recURL, &recs); err != nil {
		return Result{}, err
	}
	if len(recs) == 0 || recs[0].Hostname == "" {
		return Result{}, fmt.Errorf("nordvpn: recommendations returned no server")
	}
	cfgURL, err := ConfigURL(cdnBase, q.Protocol, recs[0].Hostname)
	if err != nil {
		return Result{}, err
	}
	body, err := getLimited(ctx, client, cfgURL, maxOVPN)
	if err != nil {
		return Result{}, err
	}
	if len(bytesTrim(body)) == 0 {
		return Result{}, fmt.Errorf("nordvpn: empty config")
	}
	return Result{Hostname: recs[0].Hostname, Body: body, ConfigURL: cfgURL}, nil
}

func countryIDByCode(ctx context.Context, client *http.Client, apiBase, code string) (int, error) {
	var countries []struct {
		ID   int    `json:"id"`
		Code string `json:"code"`
	}
	if err := getJSON(ctx, client, strings.TrimRight(apiBase, "/")+"/servers/countries", &countries); err != nil {
		return 0, err
	}
	want := strings.TrimSpace(code)
	for _, c := range countries {
		if strings.EqualFold(c.Code, want) {
			if c.ID == 0 {
				return 0, fmt.Errorf("nordvpn: country %s has no id", want)
			}
			return c.ID, nil
		}
	}
	return 0, fmt.Errorf("nordvpn: unknown country %s", want)
}

func techName(protocol string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "udp":
		return "openvpn_udp", nil
	case "tcp":
		return "openvpn_tcp", nil
	default:
		return "", fmt.Errorf("nordvpn: protocol %q", protocol)
	}
}

func protoFiles(protocol string) (dir, ext string, err error) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "udp":
		return "ovpn_udp", "udp", nil
	case "tcp":
		return "ovpn_tcp", "tcp", nil
	default:
		return "", "", fmt.Errorf("nordvpn: protocol %q", protocol)
	}
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.Contains(h, "..") {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func getJSON(ctx context.Context, client *http.Client, rawURL string, dest any) error {
	body, err := getLimited(ctx, client, rawURL, maxJSON)
	if err != nil {
		return err
	}
	if len(bytesTrim(body)) == 0 {
		return fmt.Errorf("nordvpn: empty response")
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("nordvpn: %w", err)
	}
	return nil
}

func getLimited(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nordvpn: http %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("nordvpn: response exceeds %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("nordvpn: response exceeds %d bytes", limit)
	}
	return b, nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
