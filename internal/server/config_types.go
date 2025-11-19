package server

// Settings содержит настройки сервера
type Settings struct {
	MaxCacheSizeMB int  // Максимальный размер кэша в МБ
	MaxFileSizeMB  int  // Максимальный размер файла в МБ
	ServerPort     int  // Порт сервера
	EnableLogging  bool // Включить логирование
}

// ProxyConfig содержит конфигурацию прокси-сервера
type ProxyConfig struct {
	Routes map[string]string // Маршруты прокси: путь -> URL
}