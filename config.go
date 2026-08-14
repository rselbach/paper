package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddr            = ":8080"
	defaultDBPath          = "paper.db"
	defaultSecretTTL       = 7 * 24 * time.Hour
	defaultMaxSecretBytes  = 64 * 1024
	defaultMaxStoredBytes  = 1024 * 1024 * 1024
	defaultMaxStoredItems  = 10_000
	defaultCreateRate      = 60
	defaultCleanupInterval = time.Hour
	maxRateLimitClients    = 10_000
	maxConfigDuration      = time.Duration(1<<63 - 1)
	walCheckpointTimeout   = 5 * time.Second
)

type config struct {
	addr            string
	dbPath          string
	publicOrigin    string
	secretTTL       time.Duration
	cleanupInterval time.Duration
	maxSecretBytes  int
	maxStoredBytes  int64
	maxStoredItems  int
	createRate      int
}

func loadConfig() (config, error) {
	cfg := config{
		addr:            getenv("PAPER_ADDR", defaultAddr),
		dbPath:          getenv("PAPER_DB", defaultDBPath),
		secretTTL:       defaultSecretTTL,
		cleanupInterval: defaultCleanupInterval,
		maxSecretBytes:  defaultMaxSecretBytes,
		maxStoredBytes:  defaultMaxStoredBytes,
		maxStoredItems:  defaultMaxStoredItems,
		createRate:      defaultCreateRate,
	}

	if value := os.Getenv("PAPER_PUBLIC_ORIGIN"); value != "" {
		publicOrigin, err := normalizePublicOrigin(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_PUBLIC_ORIGIN: %w", err)
		}
		cfg.publicOrigin = publicOrigin
	}

	if value := os.Getenv("PAPER_SECRET_TTL_HOURS"); value != "" {
		hours, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_SECRET_TTL_HOURS: %w", err)
		}
		if hours <= 0 {
			return config{}, fmt.Errorf("PAPER_SECRET_TTL_HOURS must be positive: %d", hours)
		}
		if hours > int64(maxConfigDuration/time.Hour) {
			return config{}, fmt.Errorf("PAPER_SECRET_TTL_HOURS is too large: %d", hours)
		}
		cfg.secretTTL = time.Duration(hours) * time.Hour
	}

	if value := os.Getenv("PAPER_CLEANUP_INTERVAL_MINUTES"); value != "" {
		minutes, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_CLEANUP_INTERVAL_MINUTES: %w", err)
		}
		if minutes <= 0 {
			return config{}, fmt.Errorf("PAPER_CLEANUP_INTERVAL_MINUTES must be positive: %d", minutes)
		}
		if minutes > int64(maxConfigDuration/time.Minute) {
			return config{}, fmt.Errorf("PAPER_CLEANUP_INTERVAL_MINUTES is too large: %d", minutes)
		}
		cfg.cleanupInterval = time.Duration(minutes) * time.Minute
	}

	if value := os.Getenv("PAPER_MAX_SECRET_BYTES"); value != "" {
		maxBytes, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_MAX_SECRET_BYTES: %w", err)
		}
		if maxBytes <= 0 {
			return config{}, fmt.Errorf("PAPER_MAX_SECRET_BYTES must be positive: %d", maxBytes)
		}
		cfg.maxSecretBytes = maxBytes
	}

	if value := os.Getenv("PAPER_MAX_STORED_BYTES"); value != "" {
		maxBytes, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_MAX_STORED_BYTES: %w", err)
		}
		if maxBytes <= 0 {
			return config{}, fmt.Errorf("PAPER_MAX_STORED_BYTES must be positive: %d", maxBytes)
		}
		cfg.maxStoredBytes = maxBytes
	}

	if value := os.Getenv("PAPER_MAX_STORED_SECRETS"); value != "" {
		maxItems, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_MAX_STORED_SECRETS: %w", err)
		}
		if maxItems <= 0 {
			return config{}, fmt.Errorf("PAPER_MAX_STORED_SECRETS must be positive: %d", maxItems)
		}
		cfg.maxStoredItems = maxItems
	}

	if value := os.Getenv("PAPER_CREATE_RATE_PER_MINUTE"); value != "" {
		createRate, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_CREATE_RATE_PER_MINUTE: %w", err)
		}
		if createRate <= 0 {
			return config{}, fmt.Errorf("PAPER_CREATE_RATE_PER_MINUTE must be positive: %d", createRate)
		}
		cfg.createRate = createRate
	}

	return cfg, nil
}

func normalizePublicOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("host is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("userinfo is not allowed")
	}
	if parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("query and fragment are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("path is not supported")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
