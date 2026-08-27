package conntrack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckAccounting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nf_conntrack_acct")
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAccounting(path); err != nil {
		t.Fatalf("enabled accounting rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckAccounting(path)
	if err == nil || !strings.Contains(err.Error(), "sysctl -w net.netfilter.nf_conntrack_acct=1") {
		t.Fatalf("disabled accounting error lacks remediation: %v", err)
	}
}

func TestCheckEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nf_conntrack_events")
	if err := os.WriteFile(path, []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckEvents(path); err != nil {
		t.Fatalf("enabled event delivery rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckEvents(path)
	if err == nil || !strings.Contains(err.Error(), "sysctl -w net.netfilter.nf_conntrack_events=1") {
		t.Fatalf("disabled event delivery error lacks remediation: %v", err)
	}
}

func TestHealthRequiresRecentSuccess(t *testing.T) {
	m := &Manager{interval: 30 * time.Second}
	if m.Healthy(time.Now()) {
		t.Fatal("manager without a successful dump is healthy")
	}
	now := time.Now()
	m.lastSuccessNanos.Store(now.Add(-time.Minute).UnixNano())
	if m.Healthy(now) {
		t.Fatal("manager without a DESTROY event listener is healthy")
	}
	m.eventConnected.Store(true)
	if !m.Healthy(now) {
		t.Fatal("manager with recent success is unhealthy")
	}
	m.lastSuccessNanos.Store(now.Add(-3 * time.Minute).UnixNano())
	if m.Healthy(now) {
		t.Fatal("manager with stale success is healthy")
	}
}
