package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jimlambrt/gldap"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	_ "github.com/qinzj/ums-ldap/docs/api"
	"github.com/qinzj/ums-ldap/internal/config"
	"github.com/qinzj/ums-ldap/internal/dao"
	"github.com/qinzj/ums-ldap/internal/ent"
	httphandler "github.com/qinzj/ums-ldap/internal/handler/http"
	ldaphandler "github.com/qinzj/ums-ldap/internal/handler/ldap"
	"github.com/qinzj/ums-ldap/internal/service"
	"github.com/qinzj/ums-ldap/pkg/logs"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP and LDAP servers",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, _ []string) error {
	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Init logger
	logs.Init(cfg.Log.ToLogsConfig())
	logger := logs.Logger()
	defer func() { _ = logger.Sync() }()

	// Ensure data directory for SQLite
	if err = cfg.Database.EnsureDataDir(); err != nil {
		logger.Fatal("failed to create data directory", zap.Error(err))
	}

	// Init Ent client
	driver := cfg.Database.Driver
	if driver == "" {
		driver = "sqlite3"
	}
	entClient, err := ent.Open(driver, cfg.Database.DSN())
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer func() { _ = entClient.Close() }()

	// Auto-migrate
	d := dao.New(entClient)
	if err := d.AutoMigrate(cmd.Context()); err != nil {
		logger.Fatal("failed to run migrations", zap.Error(err))
	}

	// Init services
	userSvc := service.NewUserService(d)
	groupSvc := service.NewGroupService(d)
	authSvc := service.NewAuthService(userSvc, cfg.JWT.Secret, cfg.JWT.ExpireHours)

	// Setup HTTP server
	router := httphandler.SetupRouter(userSvc, groupSvc, authSvc, &cfg.LDAP, logger)
	httpAddr := fmt.Sprintf(":%d", cfg.Server.HTTPPort)
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: router,
	}

	// Setup LDAP server
	ldapHandler := ldaphandler.New(userSvc, groupSvc, &cfg.LDAP, logger)
	ldapServer, err := gldap.NewServer()
	if err != nil {
		logger.Fatal("failed to create LDAP server", zap.Error(err))
	}

	mux, err := gldap.NewMux()
	if err != nil {
		logger.Fatal("failed to create LDAP mux", zap.Error(err))
	}
	ldapHandler.RegisterRoutes(mux)
	ldapServer.Router(mux)

	ldapAddr := fmt.Sprintf(":%d", cfg.LDAP.Port)

	// Error channel for server startup failures
	errCh := make(chan error, 2)

	// Start HTTP server
	go func() {
		logger.Info("HTTP server started", zap.Int("port", cfg.Server.HTTPPort))
		if err = httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start LDAP server
	go func() {
		logger.Info("LDAP server started", zap.Int("port", cfg.LDAP.Port))
		if err := ldapServer.Run(ldapAddr); err != nil {
			errCh <- fmt.Errorf("LDAP server error: %w", err)
		}
	}()

	// Wait for interrupt signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("Shutting down servers...", zap.String("signal", sig.String()))
	case err := <-errCh:
		logger.Error("Server startup failed", zap.Error(err))
		return err
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*1e9) // 10 seconds
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	if err := ldapServer.Stop(); err != nil {
		logger.Error("LDAP server shutdown error", zap.Error(err))
	}

	logger.Info("Servers stopped")
	return nil
}
