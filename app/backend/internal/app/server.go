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

// Server 封装 HTTP 生命周期；路由、鉴权和业务服务在 NewServer 中一次性完成组装。
type Server struct {
	http *http.Server
}

// NewServer 是后端的 HTTP 组合根。它在同一个路由树上明确区分公开探针、登录入口、
// 已认证只读接口和需要 CSRF/角色校验的变更接口，避免安全策略散落到各处理函数中。
func NewServer(cfg config.Config, db *sql.DB) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}

	auth := newAuthService(db)
	admin := newAdminService(db, auth)
	tasks, err := newTaskService(cfg, db)
	if err != nil {
		return nil, fmt.Errorf("initialize task service: %w", err)
	}
	models, err := newLLMService(tasks)
	if err != nil {
		return nil, fmt.Errorf("initialize model settings: %w", err)
	}
	// 恢复、请求关联 ID 和来源校验必须先于业务路由运行，确保失败请求同样可追踪且受边界保护。
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
	// authenticate 是受保护 API 的共同门禁；所有状态变更再叠加 CSRF 与最小角色要求。
	// 管理员写操作还先记录被拒绝的尝试，使权限失败也能进入审计链路。
	protected := api.Group("")
	protected.Use(auth.authenticate())
	protected.GET("/auth/me", auth.me)
	protected.POST("/auth/logout", auth.requireCSRF(), auth.logout)
	protected.POST("/auth/password", auth.requireCSRF(), auth.changePassword)
	protected.GET("/admin/users", requireAdministrator(), admin.listUsers)
	protected.POST("/admin/users", admin.auditRejectedMutation("admin.user.create"), auth.requireCSRF(), requireAdministrator(), admin.createUser)
	protected.PATCH("/admin/users/:userID", admin.auditRejectedMutation("admin.user.update"), auth.requireCSRF(), requireAdministrator(), admin.patchUser)
	protected.GET("/admin/audit", requireAdministrator(), admin.listAudit)
	registerLLMRoutes(protected, auth, models)
	protected.GET("/tasks", tasks.list)
	protected.GET("/tasks/:taskID", tasks.get)
	protected.GET("/tasks/:taskID/events", tasks.events)
	protected.GET("/tasks/:taskID/findings", tasks.findings)
	protected.GET("/tasks/:taskID/reports", tasks.listReports)
	protected.GET("/tasks/:taskID/runs/:runID/artifacts", tasks.listRunArtifacts)
	protected.GET("/tasks/:taskID/artifacts/:artifactID/content", tasks.downloadRunArtifact)
	protected.GET("/tasks/:taskID/projects/:projectID/content", tasks.downloadProject)
	protected.GET("/tasks/:taskID/projects/:projectID/source", tasks.sourcePreview)
	protected.GET("/tasks/:taskID/projects/:projectID/files", tasks.listProjectSourceFiles)
	protected.GET("/tasks/:taskID/projects/:projectID/files/:fileID/content", tasks.sourceFileContent)
	protected.GET("/tasks/:taskID/sources", tasks.downloadSources)
	protected.GET("/archive-imports", tasks.listArchiveImports)
	protected.GET("/archive-imports/:importID", tasks.getArchiveImport)
	protected.GET("/archive-imports/:importID/entries", tasks.listArchiveImportEntries)
	protected.GET("/archive-imports/:importID/report-bundles", tasks.listArchiveReportBundles)
	protected.GET("/uploads", tasks.listUploads)
	protected.GET("/uploads/:uploadID", tasks.getUpload)
	protected.GET("/reports/:reportID/content", tasks.downloadReport)
	protected.GET("/archive-report-bundles/:bundleID/content", tasks.downloadArchiveReportBundle)
	protected.POST("/uploads", auth.requireCSRF(), requireOperator(), tasks.createUpload)
	protected.PUT("/uploads/:uploadID/parts/:partNumber", auth.requireCSRF(), requireOperator(), tasks.putUploadPart)
	protected.POST("/uploads/:uploadID/complete", auth.requireCSRF(), requireOperator(), tasks.completeUpload)
	protected.POST("/uploads/:uploadID/tasks", auth.requireCSRF(), requireOperator(), tasks.createUploadTask)
	protected.DELETE("/uploads/:uploadID", auth.requireCSRF(), requireOperator(), tasks.deleteUpload)
	protected.POST("/tasks", auth.requireCSRF(), requireOperator(), tasks.create)
	protected.DELETE("/tasks/:taskID", auth.requireCSRF(), requireOperator(), tasks.delete)
	protected.POST("/tasks/:taskID/files/:fileID/archive-import", auth.requireCSRF(), requireOperator(), tasks.queueArchiveImport)
	protected.POST("/tasks/:taskID/files/:fileID/image-scan", auth.requireCSRF(), requireOperator(), tasks.queueImageScan)
	protected.POST("/tasks/:taskID/files/:fileID/decompile", auth.requireCSRF(), requireOperator(), tasks.queueDecompile)
	protected.POST("/tasks/:taskID/projects/:projectID/check", auth.requireCSRF(), requireOperator(), tasks.queueCheck)
	protected.POST("/tasks/:taskID/reports", auth.requireCSRF(), requireOperator(), tasks.createReport)
	protected.POST("/archive-imports/:importID/task-batches", auth.requireCSRF(), requireOperator(), tasks.createArchiveTaskBatch)
	protected.POST("/archive-imports/:importID/report-bundles", auth.requireCSRF(), requireOperator(), tasks.createArchiveReportBundle)

	dist, err := fs.Sub(webui.Dist, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded frontend: %w", err)
	}
	assets := http.FileServer(http.FS(dist))
	// 前端使用 SPA 回退，但 API 拼写错误必须保持 JSON 404；非只读方法也绝不能落到 index.html。
	// 这条边界既保证客户端路由可刷新，又避免 API 与静态资源命名空间互相掩盖。
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
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// requestID 接受长度受限的上游关联 ID；缺失或异常长时生成随机值，并在响应头中回传。
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

// originGuard 只约束可能改变状态的方法。浏览器携带 Origin 时必须命中配置白名单；
// 不携带 Origin 的同源旧客户端、健康探针和非浏览器调用仍由会话鉴权与 CSRF 继续保护。
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
