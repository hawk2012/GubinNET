package modules

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// compileCppModule компилирует C++ модуль
func compileCppModule(moduleDir, sourcePath string) error {
	tempDir, err := os.MkdirTemp("", "cppmod-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Копируем все файлы модуля во временную директорию
	if err := copyModuleFiles(moduleDir, tempDir); err != nil {
		return fmt.Errorf("copy module files: %w", err)
	}

	// Компилируем модуль
	objectPath := filepath.Join(tempDir, "module.so")
	cmd := exec.Command("g++", "-shared", "-fPIC", "-O2", "-std=c++17",
		"module.cpp", "-o", objectPath)
	cmd.Dir = tempDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compilation failed: %v - %s", err, stderr.String())
	}

	// Копируем скомпилированный модуль обратно
	targetSo := filepath.Join(moduleDir, "module.so")
	if err := os.Rename(objectPath, targetSo); err != nil {
		return fmt.Errorf("move compiled module: %w", err)
	}

	return nil
}

// copyModuleFiles копирует файлы модуля
func copyModuleFiles(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}

		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			return err
		}
	}

	return nil
}
