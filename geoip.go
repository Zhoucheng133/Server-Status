package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"net"

	"github.com/oschwald/geoip2-golang"
)

//go:embed geo/dbip-country-lite-2026-11.mmdb.gz
var bundledCountryDB []byte

type GeoIP struct {
	reader *geoip2.Reader
}

func openGeoIP(path string) (*GeoIP, error) {
	if path != "" {
		reader, err := geoip2.Open(path)
		if err != nil {
			return nil, err
		}
		return &GeoIP{reader: reader}, nil
	}
	z, err := gzip.NewReader(bytes.NewReader(bundledCountryDB))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	data, err := io.ReadAll(z)
	if err != nil {
		return nil, err
	}
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return nil, err
	}
	return &GeoIP{reader: reader}, nil
}

func (g *GeoIP) country(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return "Unknown"
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "Private network"
	}
	if !ip.IsGlobalUnicast() || g == nil {
		return "Unknown"
	}
	entry, err := g.reader.Country(ip)
	if err != nil || entry.Country.IsoCode == "" || entry.Country.IsoCode == "ZZ" {
		return "Unknown"
	}
	return entry.Country.IsoCode
}
