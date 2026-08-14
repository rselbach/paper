package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := openStore(ctx, cfg.dbPath, cfg.maxStoredBytes, cfg.maxStoredItems)
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("close store", "error", err)
		}
	}()

	if err := store.DeleteExpired(ctx, time.Now()); err != nil {
		logger.Error("delete expired secrets", "error", err)
		os.Exit(1)
	}
	startExpiredSecretCleaner(ctx, store, logger, cfg.cleanupInterval)

	app, err := newServer(store, logger, cfg.publicOrigin, cfg.secretTTL, cfg.maxSecretBytes, cfg.createRate)
	if err != nil {
		logger.Error("create server", "error", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.addr, "db", cfg.dbPath, "publicOrigin", cfg.publicOrigin, "cleanupInterval", cfg.cleanupInterval, "version", version)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			logger.Error("serve http", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down", "cause", context.Cause(ctx))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown http", "error", err)
		}
	}
}
