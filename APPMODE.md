# GubinNET AppMode Configuration

GubinNET поддерживает различные режимы приложений (AppMode) для обработки запросов. Режим определяется в конфигурации хоста и может быть одним из следующих:

## Поддерживаемые режимы AppMode

1. **dotnet**
   - Используется для запуска ASP.NET Core приложений
   - Требуемые параметры:
     - `DllPath` - путь к DLL файлу приложения
     - `InternalPort` - внутренний порт для приложения
   - Дополнительные настройки среды:
     - `ASPNETCORE_URLS=http://0.0.0.0:{InternalPort}`
     - `ASPNETCORE_ENVIRONMENT=Production`
     - `DOTNET_PRINT_TELEMETRY_MESSAGE=false`
     - `ASPNETCORE_SERVER_HEADER=`

2. **nodejs**
   - Используется для запуска Node.js приложений
   - Требуемые параметры (в секции NodeJS):
     - `Enabled` = true
     - `ScriptPath` - путь к основному JS файлу приложения
     - `InternalPort` - внутренний порт для приложения
   - Дополнительные настройки среды:
     - `PORT={InternalPort}`
     - `NODE_ENV=production`

3. **Прокси-режим** (когда AppMode не указан)
   - Если указан `DefaultProxy`, запросы будут проксироваться на указанный URL
   
4. **Статический файловый сервер** (когда AppMode не указан)
   - Если не настроены dotnet, nodejs или DefaultProxy, сервер будет отдавать статические файлы
   - Параметры:
     - `WebRootPath` - корневая директория для статических файлов
     - `SPAFallback` - fallback файл для одностраничных приложений

## Примеры конфигурации

### .NET приложение
```
[Host:example.com]
AppMode=dotnet
DllPath=/var/www/example/app.dll
InternalPort=5000
```

### Node.js приложение
```
[Host:example.com]
AppMode=nodejs

[NodeJS]
Enabled=true
ScriptPath=/var/www/example/app.js
InternalPort=3000
```

### Прокси-сервер
```
[Host:example.com]
DefaultProxy=http://backend-server/
```

### Статический файловый сервер
```
[Host:example.com]
WebRootPath=/var/www/html
SPAFallback=index.html
```

## Важные замечания

- Для каждого режима автоматически устанавливается соответствующее окружение и процесс управления приложением
- Сервер мониторит состояние приложений и корректно завершает их при остановке
- При использовании AppMode рекомендуется настроить SSL сертификаты для безопасного соединения
- Для .NET и Node.js приложений рекомендуется указывать InternalPort вне диапазона стандартных HTTP(S) портов
