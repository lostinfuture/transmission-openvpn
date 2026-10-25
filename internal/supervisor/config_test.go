package supervisor

import "testing"

func TestTunDevNumber(t *testing.T) {
	if mkdev(10, 200) != 2760 {
		t.Fatalf("makedev(10, 200) = %d", mkdev(10, 200))
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PUID != 1000 || cfg.PGID != 1000 || !cfg.Kill || cfg.Provider != "custom" || cfg.DCO != "auto" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.ConfigPath != "/etc/openvpn/custom/default.ovpn" {
		t.Fatal(cfg.ConfigPath)
	}
	if cfg.Source != "auto" || cfg.WebHome != "" || cfg.GitHubRepo != "haugene/vpn-configs-contrib" {
		t.Fatalf("%+v", cfg)
	}
}

func TestRejectWideLANAndRootOptIn(t *testing.T) {
	if _, err := load([]string{"LOCAL_NETWORK=0.0.0.0/0"}); err == nil {
		t.Fatal("expected /0 rejection")
	}
	if _, err := load([]string{"LOCAL_NETWORK=0.0.0.0/1,128.0.0.0/1"}); err == nil {
		t.Fatal("expected /1 rejection")
	}
	if _, err := load([]string{"LOCAL_NETWORK=10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := load([]string{"PUID=0", "PGID=0"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RootWarned {
		t.Fatal("expected root warning flag")
	}
	cfg, err = load([]string{"OPENVPN_PROVIDER=nordvpn"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "nordvpn" || cfg.ConfigPath != "" {
		t.Fatalf("nordvpn config is fetched at resolve: %+v", cfg)
	}
	if cfg.NordProtocol != "udp" {
		t.Fatal(cfg.NordProtocol)
	}
	if _, err := load([]string{"OPENVPN_PROVIDER=../x"}); err == nil {
		t.Fatal("expected provider rejection")
	}
	if _, err := load([]string{"TRANSMISSION_WEB_UI=combustion"}); err == nil {
		t.Fatal("expected web ui rejection")
	}
	cfg, err = load([]string{"ENABLE_UFW=false", "ENABLE_KILLSWITCH=true"})
	if err != nil || !cfg.Kill {
		t.Fatalf("ENABLE_UFW=false must not disable the kill switch: %+v %v", cfg, err)
	}
}

func TestFloodWebHome(t *testing.T) {
	cfg, err := load([]string{"TRANSMISSION_WEB_UI=flood"})
	if err != nil || cfg.WebHome != floodWebHome {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = load([]string{"TRANSMISSION_WEB_UI=flood-for-transmission"})
	if err != nil || cfg.WebHome != floodWebHome {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = load([]string{"TRANSMISSION_WEB_UI=transmissionic"})
	if err != nil || cfg.WebHome != transmissionicWebHome {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := load([]string{"TRANSMISSION_WEB_UI=nope"}); err == nil {
		t.Fatal("expected web ui rejection")
	}
	cfg, err = load([]string{"TRANSMISSION_WEB_UI=combustion", "TRANSMISSION_WEB_HOME=/opt/mine"})
	if err != nil || cfg.WebHome != "" {
		t.Fatalf("user home should win: %+v %v", cfg, err)
	}
}

func TestPortForwardEnv(t *testing.T) {
	cfg, err := load([]string{"OPENVPN_PROVIDER=protonvpn"})
	if err != nil || cfg.PortForward != "natpmp" || !cfg.PFFromProvider || cfg.DisablePF {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = load([]string{"OPENVPN_PROVIDER=protonvpn", "DISABLE_PORT_UPDATER=true"})
	if err != nil || cfg.PortForward != "" || cfg.PFFromProvider || !cfg.DisablePF {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = load([]string{"OPENVPN_PROVIDER=pia", "PORT_FORWARD=natpmp", "NORDVPN_PROTOCOL=TCP", "NORDVPN_COUNTRY=ch", "NORDVPN_CATEGORY=legacy_p2p", "PIA_TOKEN=tok"})
	if err != nil || cfg.PortForward != "natpmp" || cfg.PFFromProvider || cfg.NordProtocol != "tcp" || cfg.NordCountry != "ch" || cfg.NordCategory != "legacy_p2p" || cfg.PIAToken != "tok" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = load([]string{"OPENVPN_PROVIDER=pia"})
	if err != nil || cfg.PortForward != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := load([]string{"PORT_FORWARD=upnp"}); err == nil {
		t.Fatal("expected PORT_FORWARD rejection")
	}
	if _, err := load([]string{"NORDVPN_PROTOCOL=wireguard"}); err == nil {
		t.Fatal("expected protocol rejection")
	}
}

func TestRustnetEnv(t *testing.T) {
	cfg, err := load(nil)
	if err != nil || cfg.Rustnet || cfg.RustnetRefresh != 5000 || cfg.RustnetPcap != "" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = load([]string{"ENABLE_RUSTNET=true"})
	if err != nil || !cfg.Rustnet {
		t.Fatalf("ENABLE_RUSTNET=true: %+v %v", cfg, err)
	}
	cfg, err = load([]string{"ENABLE_RUSTNET=false", "RUSTNET_REFRESH_MS=1000", "RUSTNET_PCAP=/config/rustnet.pcap"})
	if err != nil || cfg.Rustnet || cfg.RustnetRefresh != 1000 || cfg.RustnetPcap != "/config/rustnet.pcap" {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := load([]string{"ENABLE_RUSTNET=maybe"}); err == nil {
		t.Fatal("expected ENABLE_RUSTNET rejection")
	}
	if _, err := load([]string{"RUSTNET_REFRESH_MS=999"}); err == nil {
		t.Fatal("expected refresh rejection")
	}
	if _, err := load([]string{"RUSTNET_REFRESH_MS=fast"}); err == nil {
		t.Fatal("expected refresh rejection")
	}
	if _, err := load([]string{"RUSTNET_PCAP=/tmp/x.pcap"}); err == nil {
		t.Fatal("expected pcap rejection")
	}
}

func TestSelfHealEnv(t *testing.T) {
	cfg, err := load(nil)
	if err != nil || cfg.SelfHeal {
		t.Fatalf("unset SELFHEAL: %+v %v", cfg, err)
	}
	cfg, err = load([]string{"SELFHEAL=true"})
	if err != nil || !cfg.SelfHeal {
		t.Fatalf("SELFHEAL=true: %+v %v", cfg, err)
	}
	if _, err := load([]string{"SELFHEAL=maybe"}); err == nil {
		t.Fatal("expected SELFHEAL rejection")
	}
}

func TestGitHubRevisionRequired(t *testing.T) {
	if _, err := load([]string{"OPENVPN_PROVIDER=pia", "VPN_CONFIG_SOURCE=github"}); err == nil {
		t.Fatal("expected revision rejection")
	}
	rev := "ff3753aadd96cca4b056f60930fa577e6e2986a3"
	cfg, err := load([]string{
		"OPENVPN_PROVIDER=pia",
		"VPN_CONFIG_SOURCE=github",
		"GITHUB_CONFIG_SOURCE_REVISION=" + rev,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source != "github" || cfg.GitHubRev != rev || cfg.ConfigPath != "" {
		t.Fatalf("%+v", cfg)
	}
	if _, err := load([]string{"VPN_CONFIG_SOURCE=github"}); err != nil {
		t.Fatal(err)
	}
	if _, err := load([]string{"OPENVPN_PROVIDER=pia", "VPN_CONFIG_SOURCE=github", "GITHUB_CONFIG_SOURCE_REVISION=FF3753AADD96CCA4B056F60930FA577E6E2986A3"}); err == nil {
		t.Fatal("expected lowercase revision")
	}
	if _, err := load([]string{"VPN_CONFIG_SOURCE=branch"}); err == nil {
		t.Fatal("expected source rejection")
	}
}
