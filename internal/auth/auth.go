package auth

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AuthManager struct {
	DB *sql.DB
}

func NewAuthManager(db *sql.DB) *AuthManager {
	return &AuthManager{DB: db}
}

// HashPassword создает хэш пароля
func (am *AuthManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword проверяет пароль
func (am *AuthManager) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Authenticate аутентифицирует пользователя
func (am *AuthManager) Authenticate(username, password string) (bool, error) {
	var storedHash string
	err := am.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	if am.CheckPassword(password, storedHash) {
		// Обновляем время последнего входа
		_, err = am.DB.Exec("UPDATE users SET last_login = ? WHERE username = ?", time.Now(), username)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

// Middleware создает middleware для аутентификации
func (am *AuthManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, является ли запрос аутентификационным
		if strings.HasPrefix(r.URL.Path, "/admin/api/auth") || r.URL.Path == "/admin/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Получаем аутентификационные данные из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Проверяем формат заголовка
		if !strings.HasPrefix(authHeader, "Basic ") {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		// Для простоты в этом примере мы будем использовать фиксированные учетные данные
		// В реальном приложении нужно использовать стандартную обработку Basic Auth
		username, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		authenticated, err := am.Authenticate(username, password)
		if err != nil {
			http.Error(w, "Authentication error", http.StatusInternalServerError)
			return
		}

		if !authenticated {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Устанавливаем имя пользователя в контексте запроса
		ctx := r.Context()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CreateUser создает нового пользователя
func (am *AuthManager) CreateUser(username, password string) error {
	hash, err := am.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	_, err = am.DB.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hash)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
}