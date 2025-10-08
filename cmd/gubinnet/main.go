package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gubinnet/internal/config"
	"gubinnet/internal/logging"
	"gubinnet/internal/server"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// Инициализация логгера
	logger := logging.NewLogger("/etc/gubinnet/logs", true)
	if logger == nil {
		return fmt.Errorf("failed to initialize logger")
	}
	defer logger.Close()
	logger.StartAutoRotate()

	// Загрузка конфигурации
	cfg, err := config.Load("/etc/gubinnet/config")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Создание сервера
	srv, err := server.New(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Запуск сервера
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	logger.Info("Server started successfully", nil)

	// Ожидание сигнала завершения
	<-ctx.Done()
	logger.Info("Shutdown signal received", nil)

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	return srv.Shutdown(shutdownCtx)
}
