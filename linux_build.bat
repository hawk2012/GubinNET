@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
set GOOS=linux
set GOARCH=amd64
set GO111MODULE=on

:: Переходим в директорию с исходным кодом
cd /path/to/project

:: Команда сборки Go-приложения
go build -o gubinnet -trimpath ./...

:: Очищаем переменные окружения после завершения
set GOOS=
set GOARCH=
set GO111MODULE=

pause