<<<<<<< HEAD
@echo off
:: Устанавливаем переменные окружения
setlocal

:: Определяем пути
set PROJECT_DIR=E:\data\YandexDisk\src\GubinNET
set RELEASE_DIR=E:\data\YandexDisk\gubinnet-release\Linux

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
if exist gubinnet (
    del gubinnet
    if errorlevel 1 (
        echo Failed to delete gubinnet.
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
set GOOS=linux
set GOARCH=amd64

:: Выполняем сборку
echo Building for %GOOS%/%GOARCH%...
set GO111MODULE=on
go build -o "%RELEASE_DIR%\gubinnet" .
if errorlevel 1 (
    echo Failed to build for %GOOS%/%GOARCH%.
    pause
    exit /b 1
)
echo Build completed for %GOOS%/%GOARCH%.

:: Очищаем переменные окружения после завершения
endlocal

=======
@echo off
:: Устанавливаем переменные окружения
setlocal

:: Определяем пути
set PROJECT_DIR=D:\GubinNET
set RELEASE_DIR=D:\data\YandexDisk\gubinnet-release\Linux

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
if exist gubinnet (
    del gubinnet
    if errorlevel 1 (
        echo Failed to delete gubinnet.
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
set GOOS=linux
set GOARCH=amd64

:: Выполняем сборку
echo Building for %GOOS%/%GOARCH%...
set GO111MODULE=on
rustc --crate-type=staticlib -o antiddos/libantiddos.a antiddos/antiddos.rs
go build -o "%RELEASE_DIR%\gubinnet" .
if errorlevel 1 (
    echo Failed to build for %GOOS%/%GOARCH%.
    pause
    exit /b 1
)
echo Build completed for %GOOS%/%GOARCH%.

:: Очищаем переменные окружения после завершения
endlocal

>>>>>>> 61df94682123fc1e94ceb7f56ab02fed36553a54
pause