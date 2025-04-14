@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
set GOOS=linux
set GOARCH=amd64

:: Переходим в директорию с исходным кодом (если нужно)

:: Команда сборки Go-приложения
go build -o gubinnet -ldflags="-s -w" -gcflags="all=-N -l" -trimpath

:: Очищаем переменные окружения после завершения
set GOOS=
set GOARCH=

pause