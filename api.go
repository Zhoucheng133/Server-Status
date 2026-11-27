package main

import (
	"log"
	"path/filepath"
	"sort"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

func (s *Service) registerRoutes(app *fiber.App) {
	app.Use("/api", func(c fiber.Ctx) error {
		c.Set("Cache-Control", "no-store")
		return c.Next()
	})
	s.registerAuthRoutes(app)
	app.Get("/api/log-sources", s.authRequired, func(c fiber.Ctx) error {
		sources, err := s.availableSources()
		if err != nil {
			return internalError(c, err)
		}
		return c.JSON(fiber.Map{"sources": sources})
	})
	app.Put("/api/settings/log-sources", s.authRequired, func(c fiber.Ctx) error {
		var request struct {
			Sources []string `json:"sources"`
		}
		if err := c.Bind().Body(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
		}
		if len(request.Sources) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "select at least one log source"})
		}
		available, err := s.availableSources()
		if err != nil {
			return internalError(c, err)
		}
		allowed := make(map[string]bool, len(available))
		for _, source := range available {
			allowed[source] = true
		}
		selected := make([]string, 0, len(request.Sources))
		seen := make(map[string]bool)
		for _, source := range request.Sources {
			if !allowed[source] {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown log source"})
			}
			if !seen[source] {
				selected = append(selected, source)
				seen[source] = true
			}
		}
		sort.Strings(selected)
		if err := s.store.setSources(selected); err != nil {
			return internalError(c, err)
		}
		s.wakeLogCollector()
		return c.JSON(fiber.Map{"sources": selected, "configured": true})
	})
	app.Get("/api/overview", func(c fiber.Ctx) error {
		data, err := s.store.overview(c.Query("site"), time.Now())
		if err != nil {
			return internalError(c, err)
		}
		return c.JSON(data)
	})
	app.Get("/api/ips", s.authRequired, func(c fiber.Ctx) error {
		items, err := s.store.recentIPs()
		if err != nil {
			return internalError(c, err)
		}
		return c.JSON(fiber.Map{"recent_ips": items})
	})
	app.Get("/api/live", s.authRequired, func(c fiber.Ctx) error {
		s.liveMu.RLock()
		defer s.liveMu.RUnlock()
		if !s.liveReady {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "metrics are initializing"})
		}
		return c.JSON(s.live)
	})
	app.Use("/api", func(c fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	})
	dist := "./frontend/dist"
	for _, route := range []string{"/", "/login", "/register"} {
		app.Get(route, func(c fiber.Ctx) error {
			return c.SendFile(filepath.Join(dist, "index.html"))
		})
	}
	app.Use(static.New(dist))
}

func internalError(c fiber.Ctx, err error) error {
	log.Printf("request failed: %v", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
}
