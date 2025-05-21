#include "security_guard.h"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <regex>
#include <cctype>
#include <ctime>
#include <unordered_set>
#include <string.h>

// URL-decode (упрощённая версия)
std::string url_decode(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '+') {
            decoded += ' ';
        } else if (str[i] == '%' && i + 2 < str.size()) {
            std::string hex = str.substr(i + 1, 2);
            char decoded_char = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
            decoded += decoded_char;
            i += 2;
        } else {
            decoded += str[i];
        }
    }
    return decoded;
}

// Парсинг строки запроса
std::unordered_map<std::string, std::string> parse_query(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    std::istringstream iss(query);
    std::string pair;

    while (std::getline(iss, pair, '&')) {
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = pair.substr(0, eq);
            std::string value = pair.substr(eq + 1);
            params[key] = url_decode(value);
        }
    }

    return params;
}

// SQL Injection Detection
int detect_sql_injection(const std::string& input) {
    std::vector<std::string> patterns = {
        "(?i)union.*select",
        "(?i)drop.*table",
        "(?i)insert\\s+into.*values",
        "(?i)delete\\s+from",
        "(?i)update.*set",
        "--",
        ";",
        "\\/\\*",
        "\\*/",
        "="
    };

    for (const auto& pattern : patterns) {
        std::regex re(pattern);
        if (std::regex_search(input, re)) {
            return 1; // SQLi обнаружен
        }
    }

    return 0;
}

// XSS Detection
int detect_xss(const std::string& input) {
    std::vector<std::string> xss_patterns = {
        "<script",
        "onload=",
        "onerror=",
        "<img",
        "<iframe",
        "javascript:",
        "eval\\(",
        "expression\\(",
        "vbscript:"
    };

    for (const auto& pattern : xss_patterns) {
        std::regex re(pattern, std::regex_constants::icase);
        if (std::regex_search(input, re)) {
            return 2; // XSS обнаружен
        }
    }

    return 0;
}

// Rate Limiting
int detect_rate_limit(int count) {
    if (count > 50) { // больше 50 запросов в минуту
        return 3; // возможный DoS
    }
    return 0;
}

// Функция, вызываемая из Go
extern "C" int check_request(
    const char* query,
    const char* post_data,
    const char* user_agent,
    const char* remote_ip,
    int request_count_in_last_minute
) {
    std::string q(query ? query : "");
    std::string pd(post_data ? post_data : "");

    std::string full_input = q + " " + pd;

    int result;

    if ((result = detect_sql_injection(full_input))) return result;
    if ((result = detect_xss(full_input))) return result;
    if ((result = detect_rate_limit(request_count_in_last_minute))) return result;

    return 0; // всё чисто
}