package main

import "testing"

func TestEmbeddedCountryLookup(t *testing.T) {
	db, err := openGeoIP("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.reader.Close()
	// Expected ISO codes are from the bundled November 2026 snapshot.
	for addr, want := range map[string]string{
		"8.8.8.8":              "US",
		"2001:4860:4860::8888": "CA",
		"192.168.1.2":          "Private network",
		"fc00::1":              "Private network",
		"invalid":              "Unknown",
	} {
		if got := db.country(addr); got != want {
			t.Errorf("country(%s) = %s, want %s", addr, got, want)
		}
	}
}
