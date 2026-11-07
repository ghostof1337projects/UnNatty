#include <chrono>
#include <ctime>
#include <string>

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    char buffer[26];  // ctime_s requires a buffer of at least 26 characters
    ctime_s(buffer, sizeof(buffer), &now_c);

    return std::string(buffer);
}
