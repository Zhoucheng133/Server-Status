package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type accessRecord struct {
	Time    float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Message string  `json:"msg"`
	Request *struct {
		ClientIP string `json:"client_ip"`
		RemoteIP string `json:"remote_ip"`
		Method   string `json:"method"`
	} `json:"request"`
}

type logPosition struct {
	offset    int64
	fileID    string
	signature string
}

type visitorBucket struct {
	ts int64
	ip string
}

func (s *Service) wakeLogCollector() {
	select {
	case s.logWake <- struct{}{}:
	default:
	}
}

func (s *Service) availableSources() ([]string, error) {
	entries, err := os.ReadDir(s.logDir)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var sources = []string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && isLogFilename(entry.Name()) {
			sources = append(sources, entry.Name())
		}
	}
	return sources, nil // os.ReadDir sorts by filename.
}

func isLogFilename(name string) bool {
	return filepath.IsLocal(name) && filepath.Base(name) == name && strings.EqualFold(filepath.Ext(name), ".json")
}

// The collector owns the open handles. A renamed or unlinked log can still be
// drained through its old handle before the replacement is read from byte zero.
func (s *Service) ingestSelectedLogs() error {
	sources, _, err := s.store.sources()
	if err != nil {
		return err
	}
	selected := make(map[string]bool, len(sources))
	for _, source := range sources {
		selected[source] = true
	}
	for source, file := range s.logFiles {
		if !selected[source] {
			file.Close()
			delete(s.logFiles, source)
		}
	}
	if s.logFiles == nil {
		s.logFiles = make(map[string]*os.File)
	}
	var failures []error
	for _, source := range sources {
		if err := s.ingestLogFile(source); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", source, err))
		}
	}
	return errors.Join(failures...)
}

func (s *Service) ingestLogFile(source string) error {
	if !isLogFilename(source) {
		return errors.New("invalid log filename")
	}
	current, err := os.Lstat(filepath.Join(s.logDir, source))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	old := s.logFiles[source]
	if old != nil {
		info, err := old.Stat()
		if err != nil {
			return err
		}
		if err := s.readLog(source, old, info); err != nil {
			return err
		}
		if current == nil || os.SameFile(info, current) {
			return nil
		}
		old.Close()
		delete(s.logFiles, source)
	}
	if current == nil {
		return nil
	}
	if !current.Mode().IsRegular() {
		return errors.New("not a regular log file")
	}
	file, err := os.OpenInRoot(s.logDir, source)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(current, info) {
		file.Close()
		return errors.New("log file changed while opening")
	}
	s.logFiles[source] = file
	return s.readLog(source, file, info)
}

func (s *Service) readLog(source string, file *os.File, info os.FileInfo) error {
	var saved logPosition
	err := s.store.db.QueryRow("SELECT offset, file_id, signature FROM log_offsets WHERE source = ?", source).
		Scan(&saved.offset, &saved.fileID, &saved.signature)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	fileID := logFileID(info)
	var start int64
	if saved.offset > 0 && saved.fileID == fileID && saved.offset <= info.Size() {
		signature, err := checkpointSignature(file, saved.offset)
		if err != nil {
			return err
		}
		if signature == saved.signature {
			start = saved.offset
		}
	}
	// Use the size at the beginning of this scan so a busy file cannot starve other sources.
	reader := bufio.NewReader(io.NewSectionReader(file, start, info.Size()-start))
	now := time.Now()
	site := strings.TrimSuffix(source, filepath.Ext(source))
	for start < info.Size() {
		traffic := make(map[int64]int)
		visitors := make(map[visitorBucket]int)
		end := start
		for range 512 {
			line, size, err := readLogLine(reader)
			if err == io.EOF {
				break // An unterminated line will be retried on the next scan.
			}
			if err != nil {
				return err
			}
			end += size
			var rec accessRecord
			if json.Unmarshal(line, &rec) != nil || rec.Request == nil || rec.Request.Method == "" {
				continue
			}
			if rec.Message != "handled request" && rec.Logger != "http.log.access" && !strings.HasPrefix(rec.Logger, "http.log.access.") {
				continue
			}
			if rec.Time < float64(now.Add(-24*time.Hour).Unix()) || rec.Time >= float64(now.Unix()+1) {
				continue
			}
			bucket := time.Unix(int64(rec.Time), 0).Truncate(sampleInterval).Unix()
			traffic[bucket]++
			addr, err := netip.ParseAddr(cleanIP(rec.Request.ClientIP))
			if err != nil {
				addr, err = netip.ParseAddr(cleanIP(rec.Request.RemoteIP))
			}
			if err == nil {
				visitors[visitorBucket{ts: bucket, ip: addr.Unmap().String()}]++
			}
		}
		if end == start {
			break
		}
		sig, err := checkpointSignature(file, end)
		if err != nil {
			return err
		}
		next := logPosition{offset: end, fileID: fileID, signature: sig}
		if err := s.commitLogBatch(source, site, saved, next, traffic, visitors); err != nil {
			return err
		}
		start, saved = end, next
	}
	return nil
}

// Bound memory even if a malformed line contains megabytes of request headers.
// Return a nil record for oversized complete lines, preserving the byte offset.
func readLogLine(reader *bufio.Reader) ([]byte, int64, error) {
	const maxLine = 2 << 20
	var size int64
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		size += int64(len(fragment))
		if size <= maxLine {
			line = append(line, fragment...)
		} else {
			line = nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, size, err
		}
	}
}

// A copy-truncated file can already exceed the old offset when polled again.
func checkpointSignature(file *os.File, offset int64) (string, error) {
	n := min(offset, 256)
	buf := make([]byte, n)
	if _, err := file.ReadAt(buf, offset-n); err != nil {
		return "", err
	}
	hash := sha256.Sum256(buf)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Service) commitLogBatch(source, site string, saved, next logPosition, traffic map[int64]int, visitors map[visitorBucket]int) error {
	countries := make(map[string]string)
	for key := range visitors {
		if _, ok := countries[key.ip]; !ok {
			countries[key.ip] = s.geo.country(key.ip)
		}
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO log_offsets (source, offset, file_id, signature) VALUES (?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET offset = excluded.offset, file_id = excluded.file_id, signature = excluded.signature
		WHERE log_offsets.offset = ? AND log_offsets.file_id = ? AND log_offsets.signature = ?`,
		source, next.offset, next.fileID, next.signature, saved.offset, saved.fileID, saved.signature)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("log checkpoint changed during scan")
	}
	for ts, count := range traffic {
		if _, err := tx.Exec(`INSERT INTO traffic_buckets (ts, site, count) VALUES (?, ?, ?)
			ON CONFLICT(ts, site) DO UPDATE SET count = count + excluded.count`, ts, site, count); err != nil {
			return err
		}
	}
	for key, count := range visitors {
		if _, err := tx.Exec(`INSERT INTO ip_buckets (ts, ip, country, count) VALUES (?, ?, ?, ?)
			ON CONFLICT(ts, ip, country) DO UPDATE SET count = count + excluded.count`, key.ts, key.ip, countries[key.ip], count); err != nil {
			return err
		}
	}
	return tx.Commit()
}
