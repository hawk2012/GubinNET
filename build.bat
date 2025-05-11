@echo off
cd /d D:\GubinNET

:: Запуск linux_build.bat в новом окне
start "Linux Build" cmd /c linux_build.bat

:: Запуск windows_build.bat в новом окне
start "Windows Build" cmd /c windows_build.bat

pause