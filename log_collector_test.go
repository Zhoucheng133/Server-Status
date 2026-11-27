package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func accessLine(ts int64, ip string) string {
	return fmt.Sprintf("{\"logger\":\"http.log.access.log0\",\"msg\":\"handled request\",\"ts\":%d,\"request\":{\"method\":\"GET\",\"host\":\"198.51.100.12\",\"client_ip\":%q}}\n", ts, ip)
}

func TestCaddyLogCheckpointAndRotation(t *testing.T) {
	dir := t.TempDir()
	store, err := openStore(filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	s := &Service{store: store, logDir: dir}
	defer func() {
		for _, f := range s.logFiles {
			f.Close()
		}
	}()
	const name = "site.example.json"
	if err := store.setSources([]string{name}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	now := time.Now().Unix() - 1
	line := accessLine(now, "192.168.1.1")
	unknown := accessLine(now, "bad address")
	stale := accessLine(now-90000, "8.8.8.8")
	future := accessLine(now+3600, "8.8.8.8")
	write := func(filename, data string, flags int) {
		t.Helper()
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|flags, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(data); err != nil {
			t.Fatal(err)
		}
	}
	check := func(visits, ips int) {
		t.Helper()
		if err := s.ingestSelectedLogs(); err != nil {
			t.Fatal(err)
		}
		var got, gotIPs int
		var site string
		if err := store.db.QueryRow("SELECT SUM(count), site FROM traffic_buckets GROUP BY site").Scan(&got, &site); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow("SELECT SUM(count) FROM ip_buckets").Scan(&gotIPs); err != nil {
			t.Fatal(err)
		}
		if got != visits || gotIPs != ips || site != "site.example" {
			t.Fatalf("visits = %d, IP visits = %d, site = %q; want %d, %d, site.example", got, gotIPs, site, visits, ips)
		}
	}

	write(path, line+unknown+stale+future+"{}\n"+line[:13], os.O_TRUNC)
	check(2, 1)
	write(path, line[13:], os.O_APPEND)
	check(3, 2)
	s.logFiles[name].Close()
	s.logFiles = nil // Reopen from persisted checkpoint.
	check(3, 2)

	// Drain the unread tail of the old file and process a larger replacement.
	write(path, line, os.O_APPEND)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	write(path, strings.Repeat(line, 12), os.O_TRUNC)
	check(16, 15)

	// Copy-truncate and regrow past the old size while keeping the inode.
	changed := accessLine(now, "192.168.1.2")
	write(path, strings.Repeat(changed, 13), os.O_TRUNC)
	check(29, 28)
	if _, err := store.db.Exec("CREATE TRIGGER fail_write BEFORE UPDATE ON ip_buckets BEGIN SELECT RAISE(FAIL, 'read only'); END"); err != nil {
		t.Fatal(err)
	}
	write(path, changed, os.O_APPEND)
	if err := s.ingestSelectedLogs(); err == nil {
		t.Fatal("expected the write error")
	}
	if _, err := store.db.Exec("DROP TRIGGER fail_write"); err != nil {
		t.Fatal(err)
	}
	check(30, 29) // Retry increments both totals exactly once.
	check(30, 29)
}
