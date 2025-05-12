@echo off
:: Устанавливаем переменные окружения
setlocal

:: Определяем пути
set PROJECT_DIR=E:\data\YandexDisk\src\GubinNET
set RELEASE_DIR=E:\data\YandexDisk\gubinnet-release\Windows

:: Создаем директорию для релизов, если она не существует
if not exist "%RELEASE_DIR%" (
    mkdir "%RELEASE_DIR%"
)

:: Переходим в корневую директорию проекта
cd /d %PROJECT_DIR%
if errorlevel 1 (
    echo Failed to change directory to %PROJECT_DIR%.
    pause
    exit /b 1
)

:: Проверяем наличие go.mod
if not exist "%PROJECT_DIR%\go.mod" (
    echo go.mod not found in %PROJECT_DIR%
    pause
    exit /b 1
)

:: Очистка предыдущих сборок (опционально)
if exist gubinnet.exe (
    del gubinnet.exe
    if errorlevel 1 (
        echo Failed to delete gubinnet.exe.
        pause
        exit /b 1
    )
)

:: Обновление зависимостей
echo Updating dependencies...
go mod tidy
if errorlevel 1 (
    echo Failed to update dependencies.
    pause
    exit /b 1
)

:: Установка целевой платформы
set GOOS=windows
set GOARCH=amd64

:: Выполняем сборку
echo Building for %GOOS%/%GOARCH%...
set GO111MODULE=on
go build -o "%RELEASE_DIR%\gubinnet.exe" .
if errorlevel 1 (
    echo Failed to build for %GOOS%/%GOARCH%.
    pause
    exit /b 1
)
echo Build completed for %GOOS%/%GOARCH%.

:: Очищаем переменные окружения после завершения
endlocal

pause