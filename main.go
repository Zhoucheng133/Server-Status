package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
)

func main() {
	dataDir := envOr("DATA_DIR", "./db")
	logDir := envOr("CADDY_LOG_DIR", "./caddy_log")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		log.Fatal(err)
	}

	store, err := openStore(filepath.Join(dataDir, "database.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.db.Close()

	geo, err := openGeoIP(os.Getenv("GEOIP_DB_PATH"))
	if err != nil {
		log.Fatalf("opening country database: %v", err)
	}
	defer geo.reader.Close()
	service := &Service{store: store, logDir: logDir, geo: geo, logWake: make(chan struct{}, 1)}
	if err := service.loadSigningKey(); err != nil {
		log.Fatal(err)
	}
	go service.runCollectors()

	app := fiber.New(fiber.Config{AppName: "Server Status"})
	service.registerRoutes(app)

	address := envOr("LISTEN_ADDR", ":3000")
	log.Printf("server status listening on %s", address)
	if err := app.Listen(address); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

const sampleInterval = 5 * time.Minute
