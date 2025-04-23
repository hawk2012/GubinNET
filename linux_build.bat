@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
set GOOS=linux
set GOARCH=amd64

:: Переходим в директорию с исходным кодом
cd /path/to/project

:: Команда сборки Go-приложения
go build -o gubinnet -trimpath ./...

:: Очищаем переменные окружения после завершения
set GOOS=
set GOARCH=

pause