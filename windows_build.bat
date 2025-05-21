@echo off
:: Устанавливаем переменные окружения
setlocal enabledelayedexpansion

:: Заголовок
title GubinNET Windows Build Script

:: Определяем пути
set PROJECT_DIR=D:\data\YandexDisk\src\GubinNET
set RELEASE_ROOT=D:\data\YandexDisk\gubinnet-release\Windows
set LOG_FILE=%RELEASE_ROOT%\build.log

:: Время начала сборки
for /f "tokens=*" %%a in ('powershell -command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"') do set BUILD_TIME=%%a

:: Создаем директорию для релизов, если она не существует
if not exist "%RELEASE_ROOT%" (
    mkdir "%RELEASE_ROOT%"
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

:: Проверяем установлен ли Go
where go >nul 2>&1
if errorlevel 1 (
    echo [%BUILD_TIME%] Go is not installed or not in PATH. >> "%LOG_FILE%"
    echo Go is not installed or not in PATH.
    pause
    exit /b 1
)

:: Очистка предыдущих сборок (опционально)
if exist gubinnet.exe (
    del gubinnet.exe
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

:: Выполняем сборку для разных архитектур
call :build windows amd64
call :build windows 386

echo.
echo Build completed successfully!
echo Release files are located in:
echo %RELEASE_ROOT%
echo.
pause
exit /b 0

:: ====================================================================================
:: Функция сборки
:build
set GOOS=%~1
set GOARCH=%~2
set TARGET_DIR=%RELEASE_ROOT%\%GOARCH%

echo Building for %GOOS%/%GOARCH%...

:: Создаём целевую папку
if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%"
)

:: Выполняем сборку
set GO111MODULE=on
go build -o "%TARGET_DIR%\gubinnet.exe" .
if errorlevel 1 (
    echo [%BUILD_TIME%] Failed to build for %GOOS%/%GOARCH%. >> "%LOG_FILE%"
    echo Failed to build for %GOOS%/%GOARCH%.
    exit /b 1
)

:: Копируем README, LICENSE и конфиги
copy /y "%PROJECT_DIR%\README.md" "%TARGET_DIR%\" >nul
copy /y "%PROJECT_DIR%\LICENSE" "%TARGET_DIR%\" >nul
if not exist "%TARGET_DIR%\config" mkdir "%TARGET_DIR%\config"
copy /y "%PROJECT_DIR%\config\*.ini" "%TARGET_DIR%\config\" >nul
if not exist "%TARGET_DIR%\modules" mkdir "%TARGET_DIR%\modules"

:: Если есть C++ модули — копируем их тоже
if exist "%PROJECT_DIR%\modules\cpp" (
    xcopy /e /i /y "%PROJECT_DIR%\modules\cpp" "%TARGET_DIR%\modules\cpp" >nul
)

echo [%BUILD_TIME%] Build completed for %GOOS%/%GOARCH%. >> "%LOG_FILE%"
echo Build completed for %GOOS%/%GOARCH%.
goto :eof