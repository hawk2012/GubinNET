@echo off
:: Устанавливаем переменные окружения для кросс-компиляции под Linux
set GOOS=linux
set GOARCH=amd64
set GO111MODULE=on

:: Переходим в корневую директорию проекта
cd E:\data\YandexDisk\Protek\src\GubinNET

:: Очистка предыдущих сборок (опционально)
if exist main del main
if exist plugins\*.so del plugins\*.so

:: Команда сборки основного приложения
echo Building main application...
go build -o main main.go

:: Проверяем успешность сборки основного приложения
if errorlevel 1 (
    echo Failed to build main application.
    pause
    exit /b 1
)

:: Компиляция плагинов
echo Building plugins...
cd plugins
for %%f in (*_main.go) do (
    echo Building plugin: %%f
    go build -buildmode=plugin -o %%~nf.so %%f
    if errorlevel 1 (
        echo Failed to build plugin: %%f
        pause
        exit /b 1
    )
)
cd ..

:: Очищаем переменные окружения после завершения
set GOOS=
set GOARCH=
set GO111MODULE=

echo Build completed successfully.
pause