@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
set GOOS=linux
set GOARCH=amd64

:: Переходим в директорию с исходным кодом (если нужно)
cd /d C:\Users\User\Desktop\GubinNET\src

:: Команда сборки Go-приложения
go build -o gubinnet

:: Очищаем переменные окружения после завершения
set GOOS=
set GOARCH=

pause