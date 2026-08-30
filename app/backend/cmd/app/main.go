package main

import (
	"context"
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

// main 是 API 服务进程的组合入口：完成配置加载、数据库迁移和初始管理员引导后，
// 才开始对外监听。这个顺序保证任何请求都不会观察到“代码已升级、表结构尚未升级”的中间状态。
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
	// 数据库连接、迁移和管理员引导共享进程级上下文；收到退出信号时，启动流程也会及时中止。
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
		// 给正在处理的请求一个有界的排空窗口，避免容器停止时直接截断报告下载或上传完成事务。
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

// healthcheck 将通配监听地址转换为本机可访问地址，并探测 /readyz 而不是仅检查端口。
// 因此容器健康状态同时覆盖 HTTP 服务存活和数据库可用性。
func healthcheck(cfg config.Config) error {
	host, port, err := net.SplitHostPort(cfg.App.ListenAddr)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	if strings.TrimSpace(host) == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(host, port) + "/readyz")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}
