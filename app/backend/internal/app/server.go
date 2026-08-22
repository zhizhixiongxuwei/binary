package app

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"binaryscan.local/backend/internal/config"
	"binaryscan.local/backend/internal/webui"

	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg    config.Config
	db     *sql.DB
	router *gin.Engine
	http   *http.Server
}

func NewServer(cfg config.Config, db *sql.DB) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	if len(cfg.App.TrustedProxyCIDRs) == 0 {
		if err := router.SetTrustedProxies(nil); err != nil {
			return nil, fmt.Errorf("disable trusted proxies: %w", err)
		}
	} else if err := router.SetTrustedProxies(cfg.App.TrustedProxyCIDRs); err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}

	auth := newAuthService(db, cfg.App.TLSMode != "http")
	router.Use(gin.Recovery(), requestID(), originGuard(cfg.App.AllowedOrigins))
	router.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	router.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c, 2*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	api := router.Group("/api/v1")
	api.GET("/system/info", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": "BinaryScan", "version": cfg.Version})
	})
	api.POST("/auth/login", auth.login)
	protected := api.Group("")
	protected.Use(auth.authenticate())
	protected.GET("/auth/me", auth.me)
	protected.POST("/auth/logout", auth.requireCSRF(), auth.logout)
	protected.POST("/auth/password", auth.requireCSRF(), auth.changePassword)

	dist, err := fs.Sub(webui.Dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded frontend: %w", err)
	}
	assets := http.FileServer(http.FS(dist))
	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		if _, err := fs.Stat(dist, strings.TrimPrefix(c.Request.URL.Path, "/")); err == nil && c.Request.URL.Path != "/" {
			assets.ServeHTTP(c.Writer, c.Request)
			return
		}
		c.Request.URL.Path = "/"
		assets.ServeHTTP(c.Writer, c.Request)
	})

	return &Server{
		cfg:    cfg,
		db:     db,
		router: router,
		http: &http.Server{
			Addr:              cfg.App.ListenAddr,
			Handler:           router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       90 * time.Second,
		},
	}, nil
}

func (s *Server) Run() error {
	if s.cfg.App.TLSMode == "direct" {
		return s.http.ListenAndServeTLS(s.cfg.App.TLSCertFile, s.cfg.App.TLSKeyFile)
	}
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		value := strings.TrimSpace(c.GetHeader("X-Request-ID"))
		if value == "" || len(value) > 64 {
			value, _, _ = secureToken(12)
		}
		c.Set("requestID", value)
		c.Header("X-Request-ID", value)
		c.Next()
	}
}

func originGuard(allowed []string) gin.HandlerFunc {
	allowlist := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowlist[strings.TrimRight(value, "/")] = struct{}{}
	}
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		origin := strings.TrimRight(strings.TrimSpace(c.GetHeader("Origin")), "/")
		if origin != "" {
			if _, ok := allowlist[origin]; !ok {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin_not_allowed"})
				return
			}
		}
		c.Next()
	}
}
