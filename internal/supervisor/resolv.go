package supervisor

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func writeResolv(path string, servers, search []string) error {
	var b strings.Builder
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	for _, s := range servers {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("dns address %q", s)
		}
		fmt.Fprintf(&b, "nameserver %s\n", addr)
	}
	if b.Len() == 0 {
		return fmt.Errorf("no nameservers")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(b.String())
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
