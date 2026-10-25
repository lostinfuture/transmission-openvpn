package supervisor

import (
	"strings"
	"testing"
)

func TestHealTick(t *testing.T) {
	next, restart, reason := healTick("203.0.113.5", false, false, false, 2)
	if next != 0 || restart || reason != "" {
		t.Fatalf("down tunnel: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("", true, false, true, 0)
	if next != 0 || !restart || reason == "" {
		t.Fatalf("missing address, empty host: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("203.0.113.5", true, false, false, 1)
	if next != 0 || !restart || reason == "" {
		t.Fatalf("missing address with a host: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("", true, true, false, 2)
	if next != 0 || restart || reason != "" {
		t.Fatalf("empty host must not dial: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("203.0.113.5", true, true, false, 0)
	if next != 1 || restart || reason != "" {
		t.Fatalf("first dial failure: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("203.0.113.5", true, true, false, 1)
	if next != 2 || restart || reason != "" {
		t.Fatalf("second dial failure: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("203.0.113.5", true, true, false, 2)
	if next != 0 || !restart || !strings.Contains(reason, "three") {
		t.Fatalf("third dial failure: %d %v %q", next, restart, reason)
	}
	next, restart, reason = healTick("203.0.113.5", true, true, true, 2)
	if next != 0 || restart || reason != "" {
		t.Fatalf("successful dial: %d %v %q", next, restart, reason)
	}
}
