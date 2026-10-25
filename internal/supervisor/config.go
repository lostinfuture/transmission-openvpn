// Package supervisor is PID 1 for the transmission-openvpn image.
//
// Remotes are rewritten to the addresses resolved when OpenVPN starts, so a
// reconnect does not depend on DNS inside the tunnel. resolv.conf is restored
// on hook-down by truncating it in place. hook-up returns after the firewall
// update. persist-tun is kept; a later hook-up restarts Transmission only when
// the tun address changes. PUID and PGID default to 1000. Torrent scripts are
// forced off. message-level is left at Transmission's own default.
package supervisor

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/lostinfuture/transmission-openvpn/internal/openvpn"
	"github.com/lostinfuture/transmission-openvpn/internal/provider"
)

// Config is the container contract for one run.
type Config struct {
	Provider       string
	ConfigPath     string
	Opts           []string
	Username       string
	Password       string
	Kill           bool
	IPv6           bool
	PeerDNS        bool
	Local          []netip.Prefix
	DropDefault    bool
	AllowGWNet     bool
	ExtraTCP       []int
	PUID           int
	PGID           int
	ApplyPerms     bool
	Home           string
	OpenFiles      int
	LogStdout      bool
	AllowUPnP      bool
	AllowScripts   bool
	DCO            string
	CreateTun      bool
	RPCUser        string
	RPCPassword    string
	HealthHost     string
	SelfHeal       bool
	Rustnet        bool
	RustnetRefresh int
	RustnetPcap    string
	RootWarned     bool
	Source         string
	GitHubRepo     string
	GitHubRev      string
	ConfigName     string
	WebHome        string
	PortForward    string
	PFFromProvider bool
	DisablePF      bool
	NordCountry    string
	NordCategory   string
	NordProtocol   string
	PIAToken       string
	PFHostname     string
}

// Load reads the process environment.
func Load() (Config, error) {
	return load(os.Environ())
}

func load(env []string) (Config, error) {
	m := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	var err error
	cfg := Config{
		Provider:   "custom",
		Home:       "/config/transmission-home",
		OpenFiles:  8192,
		Kill:       true,
		PeerDNS:    true,
		ApplyPerms: true,
		LogStdout:  true,
		CreateTun:  true,
		DCO:        "auto",
		PUID:       1000,
		PGID:       1000,
		Source:     "auto",
		GitHubRepo: provider.DefaultRepo,
	}
	if v := m["OPENVPN_PROVIDER"]; v != "" {
		name, err := provider.ValidName(v)
		if err != nil {
			return Config{}, err
		}
		cfg.Provider = name
	}
	cfg.ConfigName = m["OPENVPN_CONFIG"]
	if cfg.Provider == "custom" {
		path, err := provider.CustomPath(cfg.ConfigName)
		if err != nil {
			return Config{}, err
		}
		cfg.ConfigPath = path
	}
	if v := m["VPN_CONFIG_SOURCE"]; v != "" {
		switch strings.ToLower(v) {
		case "auto", "bundled", "github":
			cfg.Source = strings.ToLower(v)
		default:
			return Config{}, fmt.Errorf("VPN_CONFIG_SOURCE must be auto, bundled, or github")
		}
	}
	if v := m["GITHUB_CONFIG_SOURCE_REPO"]; v != "" {
		if err := provider.ValidRepo(v); err != nil {
			return Config{}, err
		}
		cfg.GitHubRepo = v
	}
	// custom stays on the bind mount. A github revision is required only when that fetch will run.
	if cfg.Source == "github" && cfg.Provider != "custom" {
		rev := m["GITHUB_CONFIG_SOURCE_REVISION"]
		if !provider.ValidRevision(rev) {
			return Config{}, fmt.Errorf("GITHUB_CONFIG_SOURCE_REVISION must be a 40-character lowercase commit")
		}
		cfg.GitHubRev = rev
	}
	if v := m["OPENVPN_OPTS"]; v != "" {
		opts, err := openvpn.SplitOpts(v)
		if err != nil {
			return Config{}, err
		}
		cfg.Opts = opts
	}
	cfg.Username = m["OPENVPN_USERNAME"]
	cfg.Password = m["OPENVPN_PASSWORD"]
	if (cfg.Username == "") != (cfg.Password == "") {
		return Config{}, fmt.Errorf("set both OPENVPN_USERNAME and OPENVPN_PASSWORD, or neither")
	}
	if cfg.Kill, err = boolEnv(m, "ENABLE_KILLSWITCH", true); err != nil {
		return Config{}, err
	}
	if _, err = boolEnv(m, "ENABLE_UFW", false); err != nil {
		return Config{}, err
	}
	if cfg.IPv6, err = boolEnv(m, "ENABLE_IPV6", false); err != nil {
		return Config{}, err
	}
	if cfg.PeerDNS, err = boolEnv(m, "PEER_DNS", true); err != nil {
		return Config{}, err
	}
	if cfg.DropDefault, err = boolEnv(m, "DROP_DEFAULT_ROUTE", false); err != nil {
		return Config{}, err
	}
	if cfg.AllowGWNet, err = boolEnv(m, "UFW_ALLOW_GW_NET", false); err != nil {
		return Config{}, err
	}
	if cfg.ApplyPerms, err = boolEnv(m, "GLOBAL_APPLY_PERMISSIONS", true); err != nil {
		return Config{}, err
	}
	if cfg.LogStdout, err = boolEnv(m, "LOG_TO_STDOUT", true); err != nil {
		return Config{}, err
	}
	if cfg.AllowUPnP, err = boolEnv(m, "ALLOW_UPNP", false); err != nil {
		return Config{}, err
	}
	if cfg.AllowScripts, err = boolEnv(m, "ALLOW_TORRENT_SCRIPTS", false); err != nil {
		return Config{}, err
	}
	if cfg.CreateTun, err = boolEnv(m, "CREATE_TUN_DEVICE", true); err != nil {
		return Config{}, err
	}
	if v := m["OPENVPN_DCO"]; v != "" {
		switch v {
		case "auto", "on", "off":
			cfg.DCO = v
		default:
			return Config{}, fmt.Errorf("OPENVPN_DCO must be auto, on, or off")
		}
	}
	if v := m["TRANSMISSION_HOME"]; v != "" {
		cfg.Home = v
	}
	if v := m["OPEN_FILES_LIMIT"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("OPEN_FILES_LIMIT %q", v)
		}
		cfg.OpenFiles = n
	}
	cfg.HealthHost = m["HEALTH_CHECK_HOST"]
	if cfg.SelfHeal, err = boolEnv(m, "SELFHEAL", false); err != nil {
		return Config{}, err
	}
	if cfg.Rustnet, err = boolEnv(m, "ENABLE_RUSTNET", false); err != nil {
		return Config{}, err
	}
	cfg.RustnetRefresh = 5000
	if v := strings.TrimSpace(m["RUSTNET_REFRESH_MS"]); v != "" {
		n, nerr := strconv.Atoi(v)
		if nerr != nil || n < 1000 {
			return Config{}, fmt.Errorf("RUSTNET_REFRESH_MS must be an integer >= 1000")
		}
		cfg.RustnetRefresh = n
	}
	pcap, err := rustnetPcap(m["RUSTNET_PCAP"])
	if err != nil {
		return Config{}, err
	}
	cfg.RustnetPcap = pcap
	cfg.RPCUser = first(m["TRANSMISSION_RPC_USERNAME"], m["TRANSMISSION_RPC_USER"])
	cfg.RPCPassword = m["TRANSMISSION_RPC_PASSWORD"]
	puidSet := m["PUID"] != ""
	pgidSet := m["PGID"] != ""
	if puidSet {
		cfg.PUID, err = strconv.Atoi(m["PUID"])
		if err != nil || cfg.PUID < 0 {
			return Config{}, fmt.Errorf("PUID %q", m["PUID"])
		}
	}
	if pgidSet {
		cfg.PGID, err = strconv.Atoi(m["PGID"])
		if err != nil || cfg.PGID < 0 {
			return Config{}, fmt.Errorf("PGID %q", m["PGID"])
		}
	}
	if puidSet && !pgidSet {
		cfg.PGID = cfg.PUID
	}
	if pgidSet && !puidSet {
		cfg.PUID = cfg.PGID
	}
	cfg.RootWarned = cfg.PUID == 0
	if err := parseNets(&cfg, m["LOCAL_NETWORK"]); err != nil {
		return Config{}, err
	}
	if v := m["UFW_EXTRA_PORTS"]; v != "" {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > 65535 {
				return Config{}, fmt.Errorf("UFW_EXTRA_PORTS %q", part)
			}
			cfg.ExtraTCP = append(cfg.ExtraTCP, n)
		}
	}
	np := strings.ToLower(strings.TrimSpace(m["NORDVPN_PROTOCOL"]))
	if np == "" {
		np = "udp"
	}
	if np != "udp" && np != "tcp" {
		return Config{}, fmt.Errorf("NORDVPN_PROTOCOL must be udp or tcp")
	}
	cfg.NordProtocol = np
	cfg.NordCountry = strings.TrimSpace(m["NORDVPN_COUNTRY"])
	cfg.NordCategory = strings.TrimSpace(m["NORDVPN_CATEGORY"])
	cfg.PIAToken = m["PIA_TOKEN"]
	switch strings.ToLower(strings.TrimSpace(m["PORT_FORWARD"])) {
	case "":
	case "natpmp":
		cfg.PortForward = "natpmp"
	default:
		return Config{}, fmt.Errorf("PORT_FORWARD must be empty or natpmp")
	}
	if cfg.DisablePF, err = boolEnv(m, "DISABLE_PORT_UPDATER", false); err != nil {
		return Config{}, err
	}
	if cfg.Provider == "protonvpn" && cfg.PortForward == "" && !cfg.DisablePF {
		cfg.PortForward = "natpmp"
		cfg.PFFromProvider = true
	}
	if m["TRANSMISSION_WEB_HOME"] == "" {
		home, err := webHome(m["TRANSMISSION_WEB_UI"])
		if err != nil {
			return Config{}, err
		}
		cfg.WebHome = home
	}
	return cfg, nil
}

func parseNets(cfg *Config, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("LOCAL_NETWORK %q: %w", part, err)
		}
		if p.Bits() < 8 {
			return fmt.Errorf("LOCAL_NETWORK %s is rejected", p)
		}
		cfg.Local = append(cfg.Local, p.Masked())
	}
	return nil
}

const floodWebHome = "/opt/transmission-ui/flood-for-transmission"
const transmissionicWebHome = "/opt/transmission-ui/transmissionic"

func webHome(v string) (string, error) {
	switch v {
	case "", "stock":
		return "", nil
	case "flood", "flood-for-transmission":
		return floodWebHome, nil
	case "transmissionic":
		return transmissionicWebHome, nil
	case "combustion", "kettu", "shift", "transmission-web-control":
		return "", fmt.Errorf("TRANSMISSION_WEB_UI=%q is not supported", v)
	default:
		return "", fmt.Errorf("TRANSMISSION_WEB_UI=%q is not supported", v)
	}
}

func boolEnv(m map[string]string, key string, def bool) (bool, error) {
	v, ok := m[key]
	if !ok || v == "" {
		return def, nil
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", key)
	}
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
