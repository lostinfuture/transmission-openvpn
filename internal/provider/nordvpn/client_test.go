package nordvpn

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestConfigURL(t *testing.T) {
	got, err := ConfigURL(CDNBase, "udp", "nl517.nordvpn.com")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://downloads.nordcdn.com/configs/files/ovpn_udp/servers/nl517.nordvpn.com.udp.ovpn"
	if got != want {
		t.Fatalf("url = %s", got)
	}
	got, err = ConfigURL(CDNBase, "tcp", "nl517.nordvpn.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "/ovpn_tcp/servers/nl517.nordvpn.com.tcp.ovpn") {
		t.Fatal(got)
	}
	if _, err := ConfigURL(CDNBase, "wireguard", "nl517.nordvpn.com"); err == nil {
		t.Fatal("expected protocol rejection")
	}
}

func TestFetchRecommendation(t *testing.T) {
	countries, err := os.ReadFile("testdata/countries.json")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := os.ReadFile("testdata/recommendations.json")
	if err != nil {
		t.Fatal(err)
	}
	const ovpn = "client\nremote 203.0.113.10 1194 udp\n"
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/servers/countries"):
			_, _ = w.Write(countries)
		case strings.HasSuffix(r.URL.Path, "/servers/recommendations"):
			gotQuery = r.URL.RawQuery
			q := r.URL.Query()
			if q.Get("limit") != "1" {
				t.Errorf("limit = %s", q.Get("limit"))
			}
			if q.Get("filters[country_id]") != "209" {
				t.Errorf("country = %s", q.Get("filters[country_id]"))
			}
			if q.Get("filters[servers_technologies][identifier]") != "openvpn_udp" {
				t.Errorf("tech = %s", q.Get("filters[servers_technologies][identifier]"))
			}
			if q.Get("filters[servers_groups][identifier]") != "legacy_p2p" {
				t.Errorf("group = %s", q.Get("filters[servers_groups][identifier]"))
			}
			_, _ = w.Write(recs)
		case strings.Contains(r.URL.Path, "/ovpn_udp/servers/nl517.nordvpn.com.udp.ovpn"):
			_, _ = w.Write([]byte(ovpn))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), srv.Client(), srv.URL, srv.URL, Query{
		Country: "nl", Protocol: "udp", Category: "legacy_p2p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Hostname != "nl517.nordvpn.com" || string(res.Body) != ovpn {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.ConfigURL, "/ovpn_udp/servers/nl517.nordvpn.com.udp.ovpn") {
		t.Fatal(res.ConfigURL)
	}
	if !strings.Contains(gotQuery, "filters") {
		t.Fatal(gotQuery)
	}
}

func TestFetchOmitsEmptyCountry(t *testing.T) {
	recs, err := os.ReadFile("testdata/recommendations.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/servers/countries") {
			t.Error("countries was requested without NORDVPN_COUNTRY")
		}
		if strings.Contains(r.URL.Path, "/servers/recommendations") {
			if _, ok := r.URL.Query()["filters[country_id]"]; ok {
				t.Error("country filter was set")
			}
			_, _ = w.Write(recs)
			return
		}
		_, _ = w.Write([]byte("client\nremote 1.2.3.4 1194 udp\n"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, srv.URL, Query{Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
}

func TestFetchFailures(t *testing.T) {
	countries, err := os.ReadFile("testdata/countries.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/servers/countries"):
			_, _ = w.Write(countries)
		case strings.HasSuffix(r.URL.Path, "/servers/recommendations"):
			_, _ = w.Write([]byte("[]"))
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, srv.URL, Query{Country: "DE"}); err == nil {
		t.Fatal("expected unknown country")
	}
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, srv.URL, Query{Country: "NL"}); err == nil {
		t.Fatal("expected empty recommendations")
	}
}

func TestFetchRejectsHugeOVPN(t *testing.T) {
	recs, err := os.ReadFile("testdata/recommendations.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "recommendations") {
			_, _ = w.Write(recs)
			return
		}
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxOVPN+1))
	}))
	defer srv.Close()
	_, err = Fetch(context.Background(), srv.Client(), srv.URL, srv.URL, Query{})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal(err)
	}
}
