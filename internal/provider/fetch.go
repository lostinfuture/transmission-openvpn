package provider

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	maxUncompressed = 96 << 20
	maxFile         = 8 << 20
	maxMembers      = 20000
)

// codeloadBase is the tarball host. Tests point it at an httptest server.
var codeloadBase = "https://codeload.github.com"

var repoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)

// ValidRepo requires owner/name. A moving branch is not a repo.
func ValidRepo(repo string) error {
	if strings.Contains(repo, "..") || !repoRE.MatchString(repo) {
		return fmt.Errorf("GITHUB_CONFIG_SOURCE_REPO %q is not an owner/name", repo)
	}
	return nil
}

// ValidRevision is a 40-character lowercase commit. Branches are refused.
func ValidRevision(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FetchGitHub downloads a pinned contrib tarball and extracts provider trees into dest.
func FetchGitHub(ctx context.Context, client *http.Client, repo, rev, dest string) error {
	return fetchGitHub(ctx, client, repo, rev, dest, MaxTarball)
}

func fetchGitHub(ctx context.Context, client *http.Client, repo, rev, dest string, max int64) error {
	if err := ValidRepo(repo); err != nil {
		return err
	}
	if !ValidRevision(rev) {
		return fmt.Errorf("GITHUB_CONFIG_SOURCE_REVISION must be a 40-character lowercase commit, not a branch")
	}
	if dest == "" || dest == "/" || dest == "." {
		return fmt.Errorf("refusing to extract into %q", dest)
	}
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codeloadBase+"/"+repo+"/tar.gz/"+rev, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ovpn-supervisor")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch vpn configs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("fetch vpn configs: %s: %s", resp.Status, strings.TrimSpace(string(buf)))
	}
	if resp.ContentLength > max {
		return fmt.Errorf("vpn config tarball exceeds %d bytes", max)
	}
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	body := &capReader{r: resp.Body, max: max}
	gz, err := gzip.NewReader(body)
	if err != nil {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("vpn config tarball: %w", err)
	}
	defer gz.Close()
	if err := extractContrib(gz, dest); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}
	if body.n > max {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("vpn config tarball exceeds %d bytes", max)
	}
	return nil
}

type capReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n > c.max {
		return 0, fmt.Errorf("vpn config tarball exceeds %d bytes", c.max)
	}
	remain := c.max - c.n + 1
	if remain < int64(len(p)) {
		p = p[:remain]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("vpn config tarball exceeds %d bytes", c.max)
	}
	return n, err
}

type storedFile struct {
	provider string
	rel      string
	body     []byte
}

func extractContrib(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	var files []storedFile
	index := map[string]int{}
	type link struct {
		member   string
		provider string
		rel      string
		target   string
	}
	var links []link
	var total int64
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("vpn config tarball: %w", err)
		}
		n++
		if n > maxMembers {
			return fmt.Errorf("vpn config tarball has too many members")
		}
		if strings.HasPrefix(hdr.Name, "/") || strings.ContainsAny(hdr.Name, "\n\r\\") || pathEscapes(hdr.Name) {
			return fmt.Errorf("vpn config tarball path %q escapes", hdr.Name)
		}
		name := path.Clean(hdr.Name)
		prov, rel, ok := splitContrib(name)
		if !ok {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if !keepRel(rel) {
				continue
			}
			if hdr.Size < 0 || hdr.Size > maxFile {
				return fmt.Errorf("vpn config file %s is too large", name)
			}
			body, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
			if err != nil {
				return err
			}
			if int64(len(body)) != hdr.Size {
				return fmt.Errorf("short read for %s", name)
			}
			total += int64(len(body))
			if total > maxUncompressed {
				return fmt.Errorf("vpn config tarball expands past %d bytes", maxUncompressed)
			}
			index[name] = len(files)
			files = append(files, storedFile{provider: prov, rel: rel, body: body})
		case tar.TypeSymlink:
			target, ok := cleanLink(hdr.Linkname)
			if !ok || !keepRel(rel) {
				continue
			}
			links = append(links, link{member: name, provider: prov, rel: rel, target: target})
		}
	}
	for _, ln := range links {
		targetName := path.Clean(path.Join(path.Dir(ln.member), ln.target))
		i, ok := index[targetName]
		if !ok {
			continue
		}
		body := files[i].body
		total += int64(len(body))
		if total > maxUncompressed {
			return fmt.Errorf("vpn config tarball expands past %d bytes", maxUncompressed)
		}
		files = append(files, storedFile{provider: ln.provider, rel: ln.rel, body: body})
	}
	if len(files) == 0 {
		return fmt.Errorf("vpn config tarball has no provider files")
	}
	for _, f := range files {
		out := filepath.Join(dest, f.provider, filepath.FromSlash(f.rel))
		if !under(dest, out) {
			return fmt.Errorf("refusing to write %s", out)
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, f.body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func pathEscapes(name string) bool {
	for _, p := range strings.Split(name, "/") {
		if p == ".." {
			return true
		}
	}
	return false
}

func splitContrib(name string) (string, string, bool) {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p != "openvpn" || i+1 >= len(parts) {
			continue
		}
		provider := parts[i+1]
		relParts := parts[i+2:]
		if len(relParts) == 0 || !safeElem(provider) || provider == "custom" {
			return "", "", false
		}
		for _, e := range relParts {
			if !safeElem(e) {
				return "", "", false
			}
		}
		return provider, strings.Join(relParts, "/"), true
	}
	return "", "", false
}

func safeElem(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\n\r")
}

func keepRel(rel string) bool {
	base := path.Base(rel)
	if base == "updateConfigs.sh" || strings.EqualFold(base, "desktop.ini") {
		return false
	}
	ext := strings.ToLower(path.Ext(base))
	switch ext {
	case ".ovpn", ".conf", ".openvpn", ".crt", ".key", ".pem", ".p12", ".cer", ".txt", ".cr":
		return true
	case "":
		return true
	default:
		return false
	}
}

func cleanLink(s string) (string, bool) {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "./") {
		s = s[2:]
	}
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, `\`) {
		return "", false
	}
	for _, p := range strings.Split(s, "/") {
		if !safeElem(p) {
			return "", false
		}
	}
	return s, true
}
