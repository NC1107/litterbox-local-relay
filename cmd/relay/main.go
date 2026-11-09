// Command relay runs the Litterbox Local push relay: it holds the maintainer's APNs key and
// forwards notifications on behalf of self-hosted Litterbox Local servers, so hosts running
// the published app get working push without ever holding the credential.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nc1107/litterbox-local-relay/internal/api"
	"github.com/nc1107/litterbox-local-relay/internal/apns"
	"github.com/nc1107/litterbox-local-relay/internal/config"
	"github.com/nc1107/litterbox-local-relay/internal/fcm"
	"github.com/nc1107/litterbox-local-relay/internal/keys"
	"github.com/nc1107/litterbox-local-relay/internal/push"
)

func main() {
	// `relay -healthcheck` hits the local health endpoint and exits 0/1. Used as the
	// container healthcheck since the distroless image has no shell or curl.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	cfg := config.Load()

	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	var ios, android push.Sender
	if cfg.APNsConfigured() {
		s, err := apns.New(apns.Config{
			KeyPath:     cfg.APNsKeyPath,
			KeyID:       cfg.APNsKeyID,
			TeamID:      cfg.APNsTeamID,
			BundleID:    cfg.APNsBundleID,
			Production:  cfg.APNsProduction,
			Concurrency: cfg.APNsConcurrency,
		})
		if err != nil {
			log.Fatalf("apns: %v", err)
		}
		ios = s
		log.Printf("relay: ios via APNs topic %q (production=%t)", cfg.APNsBundleID, cfg.APNsProduction)
	}
	if cfg.FCMCredentialsFile != "" {
		creds, err := os.ReadFile(cfg.FCMCredentialsFile)
		if err != nil {
			log.Fatalf("read FCM credentials: %v", err)
		}
		s, err := fcm.New(context.Background(), creds)
		if err != nil {
			log.Fatalf("fcm: %v", err)
		}
		android = s
		log.Printf("relay: android via Firebase project %q", s.ProjectID())
	}
	if ios == nil && android == nil {
		log.Fatal("no push provider configured: set the RELAY_APNS_* variables, and optionally RELAY_FCM_CREDENTIALS_FILE")
	}

	if dir := filepath.Dir(cfg.DBPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create db dir: %v", err)
		}
	}
	store, err := keys.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("keys store: %v", err)
	}
	defer store.Close()

	srv := api.New(cfg, ios, android, store)

	if cfg.AdminToken == "" {
		log.Println("relay: admin endpoints disabled (RELAY_ADMIN_TOKEN unset)")
	}

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("litterbox-local relay listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

// healthcheck performs a single GET against the local health endpoint, returning 0 when it
// responds 200 and 1 otherwise. Run via `relay -healthcheck` as the container probe.
func healthcheck() int {
	addr := os.Getenv("RELAY_HTTP_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + addr + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
