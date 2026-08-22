package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"binaryscan.local/backend/internal/app"
	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/database"
	"binaryscan.local/backend/migrations"
)

func main() {
	cfg, err := config.Load("app")
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, err := database.Open(ctx, cfg.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := database.Migrate(ctx, db, migrations.FS); err != nil {
		log.Fatal(err)
	}
	if err := database.BootstrapAdministrator(
		ctx, db, cfg.App.InitialAdminUser, cfg.App.InitialAdminPassword,
	); err != nil {
		log.Fatal(err)
	}

	server, err := app.NewServer(cfg, db)
	if err != nil {
		log.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Run() }()
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown failed: %v", err)
		}
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}

func healthcheck(cfg config.Config) error {
	host, port, err := net.SplitHostPort(cfg.App.ListenAddr)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	if strings.TrimSpace(host) == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.App.TLSMode == "direct" {
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // local container health probe only
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/readyz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}
