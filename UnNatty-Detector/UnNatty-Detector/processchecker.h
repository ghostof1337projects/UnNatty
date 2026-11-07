#pragma once
#include "common.h"

class ProcessChecker {
public:
    std::vector<ProcessInfo> findDiscordProcesses();
    std::vector<ProcessHistory> getCurrentProcesses();
    std::vector<ProcessHistory> getUserAssistKeys();
    void logProcessHistory();
private:
    std::string decodeRot13(const std::string& input);
};