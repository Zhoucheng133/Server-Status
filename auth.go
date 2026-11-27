package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"golang.org/x/crypto/bcrypt"
)

type tokenClaims struct {
	Subject string `json:"sub"`
	Type    string `json:"typ"`
	ID      string `json:"jti"`
	Expires int64  `json:"exp"`
	Issued  int64  `json:"iat"`
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type authRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) loadSigningKey() error {
	if configured := []byte(envOr("JWT_SECRET", "")); len(configured) != 0 {
		if len(configured) < 32 {
			return errors.New("JWT_SECRET must be at least 32 bytes")
		}
		s.signingKey = configured
		return nil
	}
	var key string
	err := s.store.db.QueryRow(`SELECT value FROM app_secrets WHERE name = 'jwt_hmac'`).Scan(&key)
	if err == nil {
		s.signingKey = []byte(key)
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	s.signingKey = []byte(base64.RawURLEncoding.EncodeToString(secret))
	_, err = s.store.db.Exec(`INSERT INTO app_secrets (name, value) VALUES ('jwt_hmac', ?)`, string(s.signingKey))
	return err
}

func (s *Service) signToken(claims tokenClaims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) verifyToken(token, expectedType string) (tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenClaims{}, errors.New("invalid token")
	}
	input := parts[0] + "." + parts[1]
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return tokenClaims{}, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, s.signingKey)
	_, _ = mac.Write([]byte(input))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return tokenClaims{}, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, errors.New("invalid token")
	}
	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Type != expectedType || claims.Subject != "1" || claims.Expires <= time.Now().Unix() || claims.ID == "" {
		return tokenClaims{}, errors.New("invalid token")
	}
	return claims, nil
}

func (s *Service) createTokenPair(tx *sql.Tx) (tokenPair, error) {
	now := time.Now()
	accessID, err := randomID()
	if err != nil {
		return tokenPair{}, err
	}
	refreshID, err := randomID()
	if err != nil {
		return tokenPair{}, err
	}
	access, err := s.signToken(tokenClaims{Subject: "1", Type: "access", ID: accessID, Issued: now.Unix(), Expires: now.Add(15 * time.Minute).Unix()})
	if err != nil {
		return tokenPair{}, err
	}
	refreshExpires := now.Add(7 * 24 * time.Hour).Unix()
	refresh, err := s.signToken(tokenClaims{Subject: "1", Type: "refresh", ID: refreshID, Issued: now.Unix(), Expires: refreshExpires})
	if err != nil {
		return tokenPair{}, err
	}
	if _, err := tx.Exec(`INSERT INTO refresh_sessions (token_hash, expires_at) VALUES (?, ?)`, refreshHash(refresh), refreshExpires); err != nil {
		return tokenPair{}, err
	}
	return tokenPair{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: 900}, nil
}

func randomID() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func refreshHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}

const bcryptSHA256Prefix = "bcrypt-sha256:"

// Encode the full password digest to fit bcrypt's 72-byte input limit.
func bcryptInput(password string) []byte {
	digest := sha256.Sum256([]byte(password))
	return base64.RawStdEncoding.AppendEncode(nil, digest[:])
}

func passwordMatches(stored, password string) bool {
	if hash, ok := strings.CutPrefix(stored, bcryptSHA256Prefix); ok {
		return bcrypt.CompareHashAndPassword([]byte(hash), bcryptInput(password)) == nil
	}
	// Older registrations used bcrypt directly and accepted at most 72 bytes.
	return len(password) <= 72 && bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
}

func (s *Service) authRequired(c fiber.Ctx) error {
	value := c.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "authentication required"})
	}
	if _, err := s.verifyToken(strings.TrimPrefix(value, "Bearer "), "access"); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired access token"})
	}
	return c.Next()
}

func (s *Service) registerAuthRoutes(app fiber.Router) {
	app.Get("/api/status", func(c fiber.Ctx) error {
		registered, err := s.store.hasAccount()
		if err != nil {
			return internalError(c, err)
		}
		_, sourcesConfigured, err := s.store.sources()
		if err != nil {
			return internalError(c, err)
		}
		return c.JSON(fiber.Map{"needs_setup": !registered, "sources_configured": sourcesConfigured})
	})
	app.Post("/api/auth/register", func(c fiber.Ctx) error {
		var request authRequest
		if err := c.Bind().Body(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
		}
		if request.Username == "" || request.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "username and password are required"})
		}
		exists, err := s.store.hasAccount()
		if err != nil {
			return internalError(c, err)
		}
		if exists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "the single account has already been created"})
		}
		hash, err := bcrypt.GenerateFromPassword(bcryptInput(request.Password), bcrypt.DefaultCost)
		if err != nil {
			return internalError(c, err)
		}
		tx, err := s.store.db.Begin()
		if err != nil {
			return internalError(c, err)
		}
		result, err := tx.Exec(`INSERT INTO users (id, username, password_hash, created_at) VALUES (1, ?, ?, ?) ON CONFLICT(id) DO NOTHING`, request.Username, bcryptSHA256Prefix+string(hash), time.Now().Unix())
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		if inserted == 0 {
			tx.Rollback()
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "the single account has already been created"})
		}
		pair, err := s.createTokenPair(tx)
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		if err := tx.Commit(); err != nil {
			return internalError(c, err)
		}
		return c.Status(fiber.StatusCreated).JSON(pair)
	})
	loginLimit := limiter.New(limiter.Config{Max: 15, Expiration: time.Minute, SkipSuccessfulRequests: true})
	app.Post("/api/auth/login", loginLimit, func(c fiber.Ctx) error {
		var request authRequest
		if err := c.Bind().Body(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
		}
		var hash string
		err := s.store.db.QueryRow(`SELECT password_hash FROM users WHERE id = 1 AND username = ?`, request.Username).Scan(&hash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return internalError(c, err)
		}
		if err != nil || !passwordMatches(hash, request.Password) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid username or password"})
		}
		tx, err := s.store.db.Begin()
		if err != nil {
			return internalError(c, err)
		}
		pair, err := s.createTokenPair(tx)
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		if err := tx.Commit(); err != nil {
			return internalError(c, err)
		}
		return c.JSON(pair)
	})
	app.Post("/api/auth/refresh", func(c fiber.Ctx) error {
		var request authRequest
		if err := c.Bind().Body(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
		}
		if _, err := s.verifyToken(request.RefreshToken, "refresh"); err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired refresh token"})
		}
		tx, err := s.store.db.Begin()
		if err != nil {
			return internalError(c, err)
		}
		result, err := tx.Exec(`DELETE FROM refresh_sessions WHERE token_hash = ? AND expires_at > ?`, refreshHash(request.RefreshToken), time.Now().Unix())
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			tx.Rollback()
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "refresh token has been revoked or reused"})
		}
		pair, err := s.createTokenPair(tx)
		if err != nil {
			tx.Rollback()
			return internalError(c, err)
		}
		if err := tx.Commit(); err != nil {
			return internalError(c, err)
		}
		return c.JSON(pair)
	})
	app.Post("/api/auth/logout", func(c fiber.Ctx) error {
		var request authRequest
		if err := c.Bind().Body(&request); err != nil || request.RefreshToken == "" {
			return c.SendStatus(fiber.StatusBadRequest)
		}
		if _, err := s.store.db.Exec(`DELETE FROM refresh_sessions WHERE token_hash = ?`, refreshHash(request.RefreshToken)); err != nil {
			return internalError(c, err)
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	app.Get("/api/auth/me", s.authRequired, func(c fiber.Ctx) error {
		var username string
		if err := s.store.db.QueryRow(`SELECT username FROM users WHERE id = 1`).Scan(&username); err != nil {
			return internalError(c, err)
		}
		sources, configured, err := s.store.sources()
		if err != nil {
			return internalError(c, err)
		}
		return c.JSON(fiber.Map{"username": username, "configured": configured, "log_sources": sources})
	})
}
