@echo off
:: Устанавливаем переменные окружения
setlocal enabledelayedexpansion

:: Заголовок
title GubinNET Build Script

:: Определяем пути
set PROJECT_DIR=D:\data\YandexDisk\src\GubinNET
set RELEASE_DIR=D:\data\YandexDisk\gubinnet-release\Linux
set LOG_FILE=%RELEASE_DIR%\build.log

:: Время начала сборки
for /f "tokens=*" %%a in ('powershell -command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set BUILD_TIME=%%a

:: Создаем директорию для релизов, если она не существует
if not exist "%RELEASE_DIR%" (
    mkdir "%RELEASE_DIR%"
)

:: Переходим в корневую директорию проекта
cd /d %PROJECT_DIR%
if errorlevel 1 (
    echo [%BUILD_TIME%] Failed to change directory to %PROJECT_DIR%. >> "%LOG_FILE%"
    echo Failed to change directory to %PROJECT_DIR%.
    pause
    exit /b 1
)

:: Проверяем наличие go.mod
if not exist "%PROJECT_DIR%\go.mod" (
    echo [%BUILD_TIME%] go.mod not found in %PROJECT_DIR% >> "%LOG_FILE%"
    echo go.mod not found in %PROJECT_DIR%
    pause
    exit /b 1
)

:: Очистка предыдущих сборок (опционально)
if exist gubinnet (
    del gubinnet
    if errorlevel 1 (
        echo [%BUILD_TIME%] Failed to delete old binary. >> "%LOG_FILE%"
        echo Failed to delete old binary.
        pause
        exit /b 1
    )
)

:: Обновление зависимостей
echo Updating dependencies...
echo [%BUILD_TIME%] Updating dependencies... >> "%LOG_FILE%"
go mod tidy
if errorlevel 1 (
    echo [%BUILD_TIME%] Failed to update dependencies. >> "%LOG_FILE%"
    echo Failed to update dependencies.
    pause
    exit /b 1
)

:: Функция сборки под разные платформы
call :build linux   amd64
call :build windows amd64
call :build darwin  amd64

echo.
echo Build completed successfully!
echo Release files are located in:
echo %RELEASE_DIR%
echo.
pause
exit /b 0

:: ====================================================================================
:: Функция сборки
:build
set GOOS=%~1
set GOARCH=%~2
set TARGET_DIR=%RELEASE_DIR%\%GOOS%\%GOARCH%

echo Building for %GOOS%/%GOARCH%...

:: Создаём целевую папку
if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%"
)

:: Выполняем сборку
set GO111MODULE=on
go build -o "%TARGET_DIR%\gubinnet" .
if errorlevel 1 (
    echo [%BUILD_TIME%] Failed to build for %GOOS%/%GOARCH%. >> "%LOG_FILE%"
    echo Failed to build for %GOOS%/%GOARCH%.
    exit /b 1
)

:: Копируем конфиги и прочие файлы (если нужно)
copy /y "%PROJECT_DIR%\README.md" "%TARGET_DIR%\" >nul
copy /y "%PROJECT_DIR%\LICENSE" "%TARGET_DIR%\" >nul
if not exist "%TARGET_DIR%\config" mkdir "%TARGET_DIR%\config"
copy /y "%PROJECT_DIR%\config\*.ini" "%TARGET_DIR%\config\" >nul
if not exist "%TARGET_DIR%\modules" mkdir "%TARGET_DIR%\modules"

echo [%BUILD_TIME%] Build completed for %GOOS%/%GOARCH%. >> "%LOG_FILE%"
echo Build completed for %GOOS%/%GOARCH%.
goto :eof