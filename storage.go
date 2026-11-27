package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Service struct {
	store      *Store
	logWake    chan struct{}
	logFiles   map[string]*os.File // owned by the log collector
	logDir     string
	geo        *GeoIP
	signingKey []byte
	liveMu     sync.RWMutex
	live       MetricSample
	liveReady  bool
}

type MetricSample struct {
	Timestamp  string  `json:"timestamp"`
	CPU        float64 `json:"cpu_percent"`
	Memory     float64 `json:"memory_percent"`
	NetworkIn  float64 `json:"network_in_bytes"`
	NetworkOut float64 `json:"network_out_bytes"`
}

type TrafficSample struct {
	Timestamp string `json:"timestamp"`
	Count     int64  `json:"count"`
}

type CountryCount struct {
	Country string `json:"country"`
	Count   int64  `json:"count"`
}

type IPCount struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Count    int64  `json:"count"`
	LastSeen string `json:"last_seen"`
}

func openStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY CHECK (id = 1), sources_json TEXT NOT NULL DEFAULT '[]',
			configured INTEGER NOT NULL DEFAULT 0
		)`,
		`INSERT OR IGNORE INTO settings (id, sources_json, configured) VALUES (1, '[]', 0)`,
		`CREATE TABLE IF NOT EXISTS app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS refresh_sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS metric_samples (
			ts INTEGER PRIMARY KEY, cpu REAL NOT NULL, memory REAL NOT NULL,
			network_in REAL NOT NULL, network_out REAL NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_buckets (
			ts INTEGER NOT NULL, site TEXT NOT NULL, count INTEGER NOT NULL,
			PRIMARY KEY (ts, site)
		)`,
		`CREATE TABLE IF NOT EXISTS ip_buckets (
			ts INTEGER NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL, count INTEGER NOT NULL,
			PRIMARY KEY (ts, ip, country)
		)`,
		`CREATE TABLE IF NOT EXISTS log_offsets (source TEXT PRIMARY KEY, offset INTEGER NOT NULL, file_id TEXT NOT NULL, signature TEXT NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) hasAccount() (bool, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id = 1)`).Scan(&exists); err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (s *Store) sources() ([]string, bool, error) {
	var encoded string
	var configured int
	err := s.db.QueryRow(`SELECT sources_json, configured FROM settings WHERE id = 1`).Scan(&encoded, &configured)
	if err != nil {
		return nil, false, err
	}
	var sources []string
	if err := json.Unmarshal([]byte(encoded), &sources); err != nil {
		return nil, false, err
	}
	return sources, configured == 1, nil
}

func (s *Store) setSources(sources []string) error {
	encoded, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE settings SET sources_json = ?, configured = 1 WHERE id = 1`, string(encoded))
	return err
}

type Overview struct {
	Metrics   []MetricSample  `json:"metrics"`
	Requests  []TrafficSample `json:"requests"`
	Countries []CountryCount  `json:"countries"`
	Sites     []string        `json:"sites"`
}

func (s *Store) overview(site string, now time.Time) (Overview, error) {
	cutoff := now.Add(-24 * time.Hour).Unix()
	out := Overview{Metrics: []MetricSample{}, Requests: []TrafficSample{}, Countries: []CountryCount{}, Sites: []string{}}
	err := s.queryRows(`SELECT ts, cpu, memory, network_in, network_out FROM metric_samples
		WHERE ts BETWEEN ? AND ? ORDER BY ts`, func(rows *sql.Rows) error {
		var ts int64
		var sample MetricSample
		if err := rows.Scan(&ts, &sample.CPU, &sample.Memory, &sample.NetworkIn, &sample.NetworkOut); err != nil {
			return err
		}
		sample.Timestamp = utcTimestamp(ts)
		out.Metrics = append(out.Metrics, sample)
		return nil
	}, cutoff, now.Unix())
	if err != nil {
		return out, err
	}
	err = s.queryRows(`SELECT ts, SUM(count) FROM traffic_buckets WHERE ts BETWEEN ? AND ?
		AND (? = '' OR site = ?) GROUP BY ts ORDER BY ts`, func(rows *sql.Rows) error {
		var sample TrafficSample
		var ts int64
		if err := rows.Scan(&ts, &sample.Count); err != nil {
			return err
		}
		sample.Timestamp = utcTimestamp(ts)
		out.Requests = append(out.Requests, sample)
		return nil
	}, cutoff, now.Unix(), site, site)
	if err != nil {
		return out, err
	}
	err = s.queryRows(`SELECT country, SUM(count) FROM ip_buckets WHERE ts BETWEEN ? AND ?
		GROUP BY country ORDER BY SUM(count) DESC, country`, func(rows *sql.Rows) error {
		var entry CountryCount
		if err := rows.Scan(&entry.Country, &entry.Count); err != nil {
			return err
		}
		out.Countries = append(out.Countries, entry)
		return nil
	}, cutoff, now.Unix())
	if err != nil {
		return out, err
	}
	err = s.queryRows(`SELECT DISTINCT site FROM traffic_buckets WHERE ts BETWEEN ? AND ? ORDER BY site`, func(rows *sql.Rows) error {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		out.Sites = append(out.Sites, name)
		return nil
	}, cutoff, now.Unix())
	return out, err
}

func utcTimestamp(ts int64) string {
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func (s *Store) recentIPs() ([]IPCount, error) {
	now := time.Now()
	items := make([]IPCount, 0)
	err := s.queryRows(`SELECT ip, country, SUM(count), MAX(ts) FROM ip_buckets WHERE ts BETWEEN ? AND ?
		GROUP BY ip, country ORDER BY MAX(ts) DESC, ip`, func(rows *sql.Rows) error {
		var entry IPCount
		var ts int64
		if err := rows.Scan(&entry.IP, &entry.Country, &entry.Count, &ts); err != nil {
			return err
		}
		entry.LastSeen = utcTimestamp(ts)
		items = append(items, entry)
		return nil
	}, now.Add(-24*time.Hour).Unix(), now.Unix())
	return items, err
}

func (s *Store) queryRows(query string, scan func(*sql.Rows) error, args ...any) error {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) prune(now time.Time) error {
	cutoff := now.Add(-24 * time.Hour).Unix()
	for _, table := range []string{"metric_samples", "traffic_buckets", "ip_buckets"} {
		if _, err := s.db.Exec(`DELETE FROM `+table+` WHERE ts < ?`, cutoff); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`DELETE FROM refresh_sessions WHERE expires_at < ?`, now.Unix())
	return err
}
