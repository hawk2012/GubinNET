#ifndef SECURITY_GUARD_H
#define SECURITY_GUARD_H

#include <string>
#include <unordered_map>

extern "C" {

// Основная функция проверки
int check_request(
    const char* query,
    const char* post_data,
    const char* user_agent,
    const char* remote_ip,
    int request_count_in_last_minute
);

// Вспомогательные функции
int detect_sql_injection(const std::string& input);
int detect_xss(const std::string& input);
int detect_rate_limit(int request_count);

}

#endif // SECURITY_GUARD_H