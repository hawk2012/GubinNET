@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
setlocal
set GOOS=linux
set GOARCH=amd64
set GO111MODULE=on

:: Переходим в корневую директорию проекта
cd /d E:\data\YandexDisk\Protek\src\GubinNET

:: Очистка предыдущих сборок (опционально)
if exist gubinnet (
    del gubinnet
)

:: Обновление зависимостей
echo Updating dependencies...
go mod tidy
if errorlevel 1 (
    echo Failed to update dependencies.
    pause
    exit /b 1
)

:: Команда сборки основного приложения
echo Building gubinnet application...
go build -o gubinnet gubinnet.go
if errorlevel 1 (
    echo Failed to build gubinnet application.
    pause
    exit /b 1
)

:: Очищаем переменные окружения после завершения
endlocal

echo Build completed successfully.
pause