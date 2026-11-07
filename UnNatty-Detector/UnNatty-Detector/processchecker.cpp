#include "processchecker.h"
#include "common.h"

void ProcessChecker::logProcessHistory() {
    std::stringstream history;

    auto processes = getCurrentProcesses();
    auto historicalProcesses = getUserAssistKeys();
    processes.insert(processes.end(), historicalProcesses.begin(), historicalProcesses.end());

    std::sort(processes.begin(), processes.end(),
        [](const ProcessHistory& a, const ProcessHistory& b) {
            return CompareFileTime(&b.timestamp, &a.timestamp) < 0;
        });

    std::set<std::string> uniquePaths;
    for (const auto& process : processes) {
        std::string lowerPath = process.path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

        if (uniquePaths.insert(lowerPath).second) {
            history << fileTimeToString(process.timestamp) << "  " << process.path << "\n";
        }
    }

    std::ofstream log("logs.txt", std::ios::app);
    log << history.str();
}

std::vector<ProcessInfo> ProcessChecker::findDiscordProcesses() {
    std::vector<ProcessInfo> foundProcesses;
    std::map<std::string, std::string> discordVersions = {
        {"discord.exe", "Discord"},
        {"discordcanary.exe", "Discord Canary"},
        {"discordptb.exe", "Discord PTB"}
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return foundProcesses;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    std::set<std::string> foundVersions;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            std::wstring wProcessName = pe32.szExeFile;
            std::string processName(wProcessName.begin(), wProcessName.end());
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            auto it = discordVersions.find(processName);
            if (it != discordVersions.end()) {
                foundVersions.insert(processName);

                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (processHandle) {
                    HMODULE modules[1024];
                    DWORD needed;
                    if (EnumProcessModules(processHandle, modules, sizeof(modules), &needed)) {
                        for (unsigned i = 0; i < (needed / sizeof(HMODULE)); i++) {
                            char modPath[MAX_PATH];
                            if (GetModuleFileNameExA(processHandle, modules[i], modPath, sizeof(modPath))) {
                                std::string modulePath = modPath;
                                if (modulePath.find("discord_voice.node") != std::string::npos) {
                                    ProcessInfo info;
                                    info.pid = pe32.th32ProcessID;
                                    info.baseAddress = (ULONGLONG)modules[i];
                                    info.path = modulePath;
                                    info.version = it->second;
                                    foundProcesses.push_back(info);
                                }
                            }
                        }
                    }
                    CloseHandle(processHandle);
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return foundProcesses;
}

std::vector<ProcessHistory> ProcessChecker::getCurrentProcesses() {
    std::vector<ProcessHistory> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (processHandle) {
                    char path[MAX_PATH];
                    if (GetModuleFileNameExA(processHandle, NULL, path, MAX_PATH)) {
                        FILETIME creation, exit, kernel, user;
                        if (GetProcessTimes(processHandle, &creation, &exit, &kernel, &user)) {
                            ProcessHistory entry;
                            entry.path = path;
                            entry.timestamp = creation;
                            processes.push_back(entry);
                        }
                    }
                    CloseHandle(processHandle);
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return processes;
}

std::vector<ProcessHistory> ProcessChecker::getUserAssistKeys() {
    std::vector<ProcessHistory> history;
    HKEY hKey;
    const char* path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char guidName[MAX_PATH];
        DWORD guidIndex = 0, guidNameSize = MAX_PATH;

        while (RegEnumKeyExA(hKey, guidIndex++, guidName, &guidNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY hSubKey;
            std::string subKeyPath = std::string(path) + "\\" + guidName + "\\Count";

            if (RegOpenKeyExA(HKEY_CURRENT_USER, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                char valueName[MAX_PATH];
                DWORD valueNameSize = MAX_PATH;
                DWORD valueIndex = 0;

                while (RegEnumValueA(hSubKey, valueIndex++, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::string decodedName = decodeRot13(valueName);
                    std::transform(decodedName.begin(), decodedName.end(), decodedName.begin(), ::tolower);

                    if (decodedName.find(".exe") != std::string::npos) {
                        BYTE data[1024];
                        DWORD dataSize = sizeof(data);
                        if (RegQueryValueExA(hSubKey, valueName, NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
                            if (dataSize >= 68) {
                                ProcessHistory entry;
                                entry.path = decodedName;
                                memcpy(&entry.timestamp, data + 60, sizeof(FILETIME));
                                history.push_back(entry);
                            }
                        }
                    }
                    valueNameSize = MAX_PATH;
                }
                RegCloseKey(hSubKey);
            }
            guidNameSize = MAX_PATH;
        }
        RegCloseKey(hKey);
    }
    return history;
}

std::string ProcessChecker::decodeRot13(const std::string& input) {
    std::string result = input;
    for (char& c : result) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            c = (c - base + 13) % 26 + base;
        }
    }
    return result;
}
