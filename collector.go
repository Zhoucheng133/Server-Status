package main

import (
	"errors"
	"log"
	netutil "net"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	netstat "github.com/shirou/gopsutil/v4/net"
)

type interfaceCounters struct {
	received uint64
	sent     uint64
}

type metricTotals struct {
	cpu        float64
	memory     float64
	networkIn  float64
	networkOut float64
	count      int
}

func cleanIP(value string) string {
	value = strings.TrimSpace(value)
	if host, _, err := netutil.SplitHostPort(value); err == nil {
		return host
	}
	return strings.Trim(value, "[]")
}

func (s *Service) runCollectors() {
	go s.runMetricCollector()
	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()
	for {
		if err := s.ingestSelectedLogs(); err != nil {
			log.Printf("caddy log collection failed: %v", err)
		}
		if err := s.store.prune(time.Now()); err != nil {
			log.Printf("history cleanup failed: %v", err)
		}
		select {
		case <-ticker.C:
		case <-s.logWake:
		}
	}
}

func (s *Service) runMetricCollector() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	_, _ = cpu.Percent(0, false) // establish the CPU baseline for the first interval
	previous, previousErr := readNetworkCounters()
	previousAt := time.Now()
	var totals metricTotals
	window := previousAt.Truncate(sampleInterval)

	for range ticker.C {
		network, networkErr := readNetworkCounters()
		now := time.Now()
		seconds := now.Sub(previousAt).Seconds()
		baseline, baselineErr := previous, previousErr
		previous, previousErr, previousAt = network, networkErr, now
		if bucket := now.Truncate(sampleInterval); bucket.After(window) {
			if totals.count > 0 {
				count := float64(totals.count)
				average := MetricSample{
					Timestamp: window.UTC().Format(time.RFC3339),
					CPU:       totals.cpu / count, Memory: totals.memory / count,
					NetworkIn: totals.networkIn / count, NetworkOut: totals.networkOut / count,
				}
				if err := s.saveMetric(average); err != nil {
					log.Printf("saving metric sample: %v", err)
				}
			}
			window, totals = bucket, metricTotals{}
		}
		percent, cpuErr := cpu.Percent(0, false)
		memory, memErr := mem.VirtualMemory()
		if cpuErr != nil || len(percent) == 0 || memErr != nil || networkErr != nil || baselineErr != nil || seconds <= 0 {
			log.Printf("metric sample unavailable (cpu=%v memory=%v network=%v)", cpuErr, memErr, networkErr)
			s.liveMu.Lock()
			s.liveReady = false
			s.liveMu.Unlock()
			continue
		}
		current := MetricSample{
			Timestamp: now.UTC().Format(time.RFC3339),
			CPU:       percent[0], Memory: memory.UsedPercent,
			NetworkIn:  byteRate(baseline.received, network.received, seconds),
			NetworkOut: byteRate(baseline.sent, network.sent, seconds),
		}
		s.liveMu.Lock()
		s.live, s.liveReady = current, true
		s.liveMu.Unlock()
		totals.cpu += current.CPU
		totals.memory += current.Memory
		totals.networkIn += current.NetworkIn
		totals.networkOut += current.NetworkOut
		totals.count++
	}
}

// Network interfaces can disappear or reset their byte counters.
func byteRate(previous, current uint64, seconds float64) float64 {
	if current <= previous {
		return 0
	}
	return float64(current-previous) / seconds
}

func readNetworkCounters() (interfaceCounters, error) {
	values, err := netstat.IOCounters(false)
	if err != nil {
		return interfaceCounters{}, err
	}
	if len(values) == 0 {
		return interfaceCounters{}, errors.New("no network interfaces")
	}
	return interfaceCounters{received: values[0].BytesRecv, sent: values[0].BytesSent}, nil
}

func (s *Service) saveMetric(sample MetricSample) error {
	ts, err := time.Parse(time.RFC3339, sample.Timestamp)
	if err != nil {
		return err
	}
	_, err = s.store.db.Exec(`INSERT INTO metric_samples (ts, cpu, memory, network_in, network_out)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(ts) DO UPDATE SET cpu=excluded.cpu, memory=excluded.memory,
		network_in=excluded.network_in, network_out=excluded.network_out`,
		ts.Unix(), sample.CPU, sample.Memory, sample.NetworkIn, sample.NetworkOut)
	return err
}
