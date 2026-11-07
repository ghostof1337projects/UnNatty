#include "common.h"
#include "hookdetector.h"
#include "processchecker.h"
#include "cosa.h"
#include <thread>
#include <chrono>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <filesystem>
#include <unordered_map>
#include <iomanip>
#include <cctype>
#include <conio.h>
#include <Windows.h>
#include "timestamp.h"
#include <mutex>
#include <atomic>
#include <future>
#include <algorithm>

struct ModuleInfo {
    DWORD processId;
    MODULEENTRY32W moduleEntry;
    bool found;
    std::wstring processName;
    void* textSectionAddress;
    SIZE_T textSectionSize;
    std::wstring cleanNodePath;
};

struct DiscordPaths {
    std::wstring mainPath;
    std::wstring canaryPath;
    std::wstring ptbPath;
};

struct VoiceNodeInfo {
    std::string type;
    DWORD pid;
    size_t size;
};

DiscordPaths GetCleanVoiceNodePaths() {
    DiscordPaths paths;
    wchar_t localAppData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        std::filesystem::path baseDir(localAppData);

        const std::vector<std::pair<std::wstring, std::wstring*>> discordTypes = {
            {L"Discord", &paths.mainPath},
            {L"DiscordCanary", &paths.canaryPath},
            {L"DiscordPTB", &paths.ptbPath}
        };

        for (const auto& [discordType, pathPtr] : discordTypes) {
            std::filesystem::path discordPath = baseDir / discordType;
            if (!std::filesystem::exists(discordPath)) continue;

            std::wstring latestVersion;
            std::filesystem::path latestPath;

            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                if (entry.is_directory() && entry.path().filename().wstring().find(L"app-") == 0) {
                    std::wstring version = entry.path().filename().wstring().substr(4);
                    if (version > latestVersion) {
                        latestVersion = version;
                        latestPath = entry.path();
                    }
                }
            }

            if (!latestPath.empty()) {

                auto modulePath = latestPath / L"modules";
                for (const auto& entry : std::filesystem::directory_iterator(modulePath)) {
                    std::wstring dirName = entry.path().filename().wstring();
                    if (entry.is_directory() && dirName.find(L"discord_voice-") == 0) {
                        *pathPtr = (entry.path() / L"discord_voice" / L"discord_voice.node").wstring();
                        break;
                    }
                }
            }
        }
    }
    return paths;
}
wchar_t* wcscasestr(const wchar_t* haystack, const wchar_t* needle) {
    if (!*needle) return (wchar_t*)haystack;
    for (; *haystack; ++haystack) {
        if (towlower(*haystack) == towlower(*needle)) {
            const wchar_t* h = haystack;
            const wchar_t* n = needle;
            while (*h && *n && towlower(*h) == towlower(*n)) {
                ++h;
                ++n;
            }
            if (!*n) return (wchar_t*)haystack;
        }
    }
    return nullptr;
}

std::wstring GetDiscordVoiceNodePath(const std::wstring& processPath) {
    try {
        std::filesystem::path exePath(processPath);
        std::filesystem::path appDir = exePath.parent_path();

        for (const auto& entry : std::filesystem::directory_iterator(appDir)) {
            if (entry.is_directory() && entry.path().filename().string().find("modules") != std::string::npos) {

                for (const auto& modEntry : std::filesystem::directory_iterator(entry)) {
                    std::string dirName = modEntry.path().filename().string();
                    if (modEntry.is_directory() && dirName.find("discord_voice-") == 0) {

                        std::filesystem::path nodePath = modEntry.path() / "discord_voice" / "discord_voice.node";
                        if (std::filesystem::exists(nodePath)) {
                            return nodePath.wstring();
                        }
                    }
                }
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {

        OutputDebugStringA(e.what());
    }
    catch (...) {

    }
    return L"";

}
size_t getDiscordVoiceNodeFileSize(DWORD pid, const std::string& moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &moduleEntry)) {
        do {
            std::wstring moduleNameW(moduleName.begin(), moduleName.end());
            if (wcscasestr(moduleEntry.szModule, moduleNameW.c_str()) != nullptr) {
                CloseHandle(snapshot);
                HANDLE hFile = CreateFileW(moduleEntry.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    LARGE_INTEGER fileSize;
                    if (GetFileSizeEx(hFile, &fileSize)) {
                        CloseHandle(hFile);
                        return fileSize.QuadPart;
                    }
                    CloseHandle(hFile);
                }
                return 0;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }
    CloseHandle(snapshot);
    return 0;

}
std::string formatVoiceNodeSize(size_t sizeInBytes) {
    size_t sizeInKB = sizeInBytes / 1024;
    std::ostringstream formattedSize;
    
    // Format with commas for readability (e.g., 17,960)
    std::string sizeStr = std::to_string(sizeInKB);
    int pos = sizeStr.length() - 3;
    while (pos > 0) {
        sizeStr.insert(pos, ",");
        pos -= 3;
    }
    
    formattedSize << sizeStr << " KB (" << sizeInBytes << " bytes)";
    return formattedSize.str();
}

std::vector<VoiceNodeInfo> getVoiceNodeInfo() {
    std::vector<VoiceNodeInfo> nodeInfo;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return nodeInfo;

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            std::wstring processName = processEntry.szExeFile;
            std::string type;
            if (processName == L"Discord.exe") type = "Discord";
            else if (processName == L"DiscordPTB.exe") type = "Discord PTB";
            else if (processName == L"DiscordCanary.exe") type = "Discord Canary";
            else continue;

            size_t fileSize = getDiscordVoiceNodeFileSize(processEntry.th32ProcessID, "discord_voice.node");
            if (fileSize > 0) {
                nodeInfo.push_back({ type, processEntry.th32ProcessID, fileSize });
            }
        } while (Process32NextW(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return nodeInfo;
}

void runUnnattyDetector();
void runUnNattyBreaker();
bool IsElevated();
bool RunAsAdmin();
void enableConsoleColors();
void clearScreen();
void printMainMenu();
void KillTheseNiggers();
std::vector<ModuleInfo> WhyIsAscendSuchABadCoder();
std::wstring ThatsToGetClientsYouTrashAssNigger(const std::wstring& processName);
bool TerryDavisMyGoat(const ModuleInfo& moduleInfo);
void YureiIsBetterThanAscend(const std::vector<ModuleInfo>& modules);
void IHateNiggers();
void AscendIsBlack();
void ThatsIsForConsoleColorsYouFatFuck(int color);
std::string OracleShouldBeListOwnerFr();
std::string GetDots();
void ThatsACIAGuyRightThere(const std::string& text);
void TheNiggaCaddle();

void clearScreen() {
    system("cls");
}

void printMainMenu() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << R"(
    ╔══════════════════════════════════════════════════════╗
    ║                   Created by Oracle                  ║
    ║                   Modded by Ghost of 1337            ║
    ╠══════════════════════════════════════════════════════╣
    ║                                                      ║
    ║    [1] UnNatty Detector                              ║
    ║    [2] UnNatty Breaker                               ║
    ║                                                      ║
    ║    [X] Exit                                          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
)" << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated;
}

bool RunAsAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei)) {
            return false;
        }
        return true;
    }
    return false;
}

void enableConsoleColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
}

void ThatsIsForConsoleColorsYouFatFuck(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

std::string OracleShouldBeListOwnerFr() {
    static int animationFrame = 0;
    const std::string frames[] = { " |", " /", " -", " \\" };
    animationFrame = (animationFrame + 1) % 4;
    return frames[animationFrame];
}

std::string GetDots() {
    static int dotCount = 0;
    dotCount = (dotCount + 1) % 4;
    return std::string(dotCount, '.');
}

void ThatsACIAGuyRightThere(const std::string& text) {
    std::cout << "  " << text << std::endl;
}

void TheNiggaCaddle() {
    system("cls");
    ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::cout << "\n";
    std::cout << "  =======================================\n";
    std::cout << "         UnNattyBreaker v1.1.0\n";
    std::cout << "      Best Runtime Hook Detector\n";
    std::cout << "  =======================================\n";
    std::cout << "\n";
    ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void KillTheseNiggers() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry = { sizeof(processEntry) };
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (wcsstr(processEntry.szExeFile, L"Discord") != nullptr) {
                    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                    if (process != NULL) {
                        TerminateProcess(process, 0);
                        CloseHandle(process);
                    }
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
}

std::vector<ModuleInfo> WhyIsAscendSuchABadCoder() {
    std::vector<ModuleInfo> modules;
    const wchar_t* targetProcesses[] = { L"Discord.exe", L"DiscordCanary.exe", L"DiscordPTB.exe" };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return modules;

    PROCESSENTRY32W processEntry = { sizeof(processEntry) };
    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            for (const auto& targetProcess : targetProcesses) {
                if (_wcsicmp(processEntry.szExeFile, targetProcess) == 0) {
                    HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                        processEntry.th32ProcessID);

                    if (moduleSnap != INVALID_HANDLE_VALUE) {
                        MODULEENTRY32W moduleEntry = { sizeof(moduleEntry) };

                        if (Module32FirstW(moduleSnap, &moduleEntry)) {
                            do {
                                if (_wcsicmp(moduleEntry.szModule, L"discord_voice.node") == 0) {
                                    ModuleInfo info = { 0 };
                                    info.processId = processEntry.th32ProcessID;
                                    info.moduleEntry = moduleEntry;
                                    info.found = true;
                                    info.processName = processEntry.szExeFile;

                                    wchar_t localAppData[MAX_PATH];
                                    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
                                        std::filesystem::path baseDir(localAppData);
                                        std::wstring discordType;

                                        if (info.processName.find(L"DiscordCanary") != std::wstring::npos) {
                                            discordType = L"DiscordCanary";
                                        }
                                        else if (info.processName.find(L"DiscordPTB") != std::wstring::npos) {
                                            discordType = L"DiscordPTB";
                                        }
                                        else {
                                            discordType = L"Discord";
                                        }

                                        std::filesystem::path discordPath = baseDir / discordType;
                                        if (std::filesystem::exists(discordPath)) {
                                            std::wstring latestVersion;
                                            std::filesystem::path latestPath;

                                            for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                                                if (entry.is_directory() && entry.path().filename().wstring().find(L"app-") == 0) {
                                                    std::wstring version = entry.path().filename().wstring().substr(4);
                                                    if (version > latestVersion) {
                                                        latestVersion = version;
                                                        latestPath = entry.path();
                                                    }
                                                }
                                            }

                                            if (!latestPath.empty()) {
                                                auto modulePath = latestPath / L"modules";
                                                for (const auto& entry : std::filesystem::directory_iterator(modulePath)) {
                                                    std::wstring dirName = entry.path().filename().wstring();
                                                    if (entry.is_directory() && dirName.find(L"discord_voice-") == 0) {
                                                        info.cleanNodePath = (entry.path() / L"discord_voice" / L"discord_voice.node").wstring();
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    modules.push_back(info);
                                }
                            } while (Module32NextW(moduleSnap, &moduleEntry));
                        }
                        CloseHandle(moduleSnap);
                    }
                }
            }
        } while (Process32NextW(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return modules;
}

std::wstring ThatsToGetClientsYouTrashAssNigger(const std::wstring& processName) {
    const wchar_t* discord = L"Discord.exe";
    const wchar_t* canary = L"DiscordCanary.exe";
    const wchar_t* ptb = L"DiscordPTB.exe";
    if (processName == discord) return std::wstring(L"Discord");
    if (processName == canary) return std::wstring(L"Canary");
    if (processName == ptb) return std::wstring(L"PTB");
    return std::wstring(L"Unknown");
}

bool TerryDavisMyGoat(const ModuleInfo& moduleInfo) {
    if (moduleInfo.cleanNodePath.empty()) return false;

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, moduleInfo.processId);
    if (!process) return false;

    HANDLE file = CreateFileW(moduleInfo.cleanNodePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        CloseHandle(process);
        return false;
    }

    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(file);
    if (!mapping) {
        CloseHandle(process);
        return false;
    }

    void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(mapping);
        CloseHandle(process);
        return false;
    }

    bool success = false;
    try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)view;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)view + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sections[i].Name, ".text", 5) == 0) {
                void* targetAddr = (BYTE*)moduleInfo.moduleEntry.modBaseAddr + sections[i].VirtualAddress;
                void* sourceData = (BYTE*)view + sections[i].PointerToRawData;
                SIZE_T sectionSize = sections[i].SizeOfRawData;

                DWORD oldProtect;
                if (VirtualProtectEx(process, targetAddr, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    if (WriteProcessMemory(process, targetAddr, sourceData, sectionSize, nullptr)) {
                        VirtualProtectEx(process, targetAddr, sectionSize, oldProtect, &oldProtect);
                        success = true;
                    }
                }
                break;
            }
        }
    }
    catch (...) {
        success = false;
    }

    UnmapViewOfFile(view);
    CloseHandle(mapping);
    CloseHandle(process);
    return success;
}

void YureiIsBetterThanAscend(const std::vector<ModuleInfo>& modules) {
    static std::string lastMessage;
    const size_t MAX_MESSAGE_LENGTH = 79;

    try {
        if (modules.empty()) {
            std::string message = "  Monitoring processes with discord_voice.node loaded...";
            if (message != lastMessage) {
                std::cout << "\r" << std::string(MAX_MESSAGE_LENGTH, ' ') << "\r" << message << std::flush;
                lastMessage = message;
            }
            return;
        }

        std::string currentMessage = "\n  Monitor:\n";
        for (const auto& module : modules) {
            currentMessage += "  " + std::string(module.processName.begin(), module.processName.end()) +
                " (PID: " + std::to_string(module.processId) + ")\n";
        }

        if (currentMessage != lastMessage) {

            for (int i = 0; i < 10; i++) {
                std::cout << "\r" << std::string(MAX_MESSAGE_LENGTH, ' ') << "\n";
            }
            std::cout << "\r";

            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(hConsole, &csbi);
            COORD newPos = { 0, csbi.dwCursorPosition.Y - 10 };
            SetConsoleCursorPosition(hConsole, newPos);

            ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << currentMessage << std::flush;
            ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

            lastMessage = currentMessage;
        }
    }
    catch (...) {
        ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        throw;
    }
}

void IHateNiggers() {
    static const int suspiciousKeys[] = {
        VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9, VK_F10,
        VK_INSERT, VK_HOME, VK_DELETE, VK_END, VK_PRIOR, VK_NEXT,
        VK_UP, VK_DOWN, VK_LEFT, VK_RIGHT, VK_PAUSE
    };

    static const char* keyNames[] = {
        ("F2"), ("F3"), ("F4"), ("F5"), ("F6"),
        ("F7"), ("F8"), ("F9"), ("F10"),
        ("INSERT"), ("HOME"), ("DELETE"), ("END"),
        ("PAGE UP"), ("PAGE DOWN"), ("UP ARROW"),
        ("DOWN ARROW"), ("LEFT ARROW"), ("RIGHT ARROW"),
        ("PAUSE")
    };

    for (int i = 0; i < 20; i++) {
        if (GetAsyncKeyState(suspiciousKeys[i]) & 1) {
            std::string message = "Why did you press ";
            message += keyNames[i];
            message += "? Suspicious...";
            MessageBoxA(NULL, message.c_str(), "Ascend Larp Detected", MB_ICONWARNING | MB_OK);
            TheNiggaCaddle();
        }
    }
}

void AscendIsBlack() {
    try {
        while (true) {
            try {
                IHateNiggers();
                auto modules = WhyIsAscendSuchABadCoder();
                if (!modules.empty()) {
                    YureiIsBetterThanAscend(modules);
                    for (const auto& module : modules) {
                        TerryDavisMyGoat(module);
                    }
                }
                else {
                    std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
                    ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::string message = "  Waiting for Discord";
                    message += GetDots();
                    std::cout << message << std::flush;
                    ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                }
            }
            catch (...) {

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    catch (...) {

        throw;
    }
}

void runUnnattyDetector() {
    try {
        SystemLogger logger;
        clearScreen();
        std::cout << BLUE << R"(
=======================================================
                UnNatty-Detector v2.2.0 
                 Created by Oracle              
=======================================================)" << RESET << std::endl;

        ProcessChecker processChecker;
        HookDetector hookDetector;
        std::cout << BLUE << "[*] Scanning for Discord processes...\n\n" << RESET;
        auto processes = processChecker.findDiscordProcesses();
        auto voiceNodes = getVoiceNodeInfo();

        if (processes.empty()) {
            std::cout << RED << "[!] No Discord installations found\n" << RESET;
            std::cout << BLUE << "\n[*] Press Enter to return to menu..." << RESET;
            std::cin.get();
            return;
        }

        std::ofstream log("logs.txt", std::ios::trunc);
        log << "=======================================================\n";
        log << "                UnNatty-Detector v2.1.2\n";
        log << "Created by Oracle (Credit to Cosa for external detection)\n";
        log << "=======================================================\n\n";
        log << "Scan Started: " << getCurrentTimestamp() << "\n\n";
        log << "[*] Discord Process Information\n";
        log << "-------------------------------------------------------\n\n";
        log.close();

        log.open("logs.txt", std::ios::app);
        std::unordered_map<std::string, bool> foundDiscordVersions = {
            {"Discord", false},
            {"Discord PTB", false},
            {"Discord Canary", false}
        };

        for (const auto& process : processes) {
            for (const auto& node : voiceNodes) {
                if (!foundDiscordVersions[node.type] && node.type == process.version) {
                    std::cout << GREEN << "[+] Found " << node.type << " (PID: " << process.pid << ")\n" << RESET;
                    std::cout << BLUE << "    Voice Node Found at: 0x" << std::hex << process.baseAddress << std::dec << "\n";
                    std::cout << "    Voice Node Size: " << formatVoiceNodeSize(node.size) << "\n";
                    
                    size_t sizeInKB = node.size / 1024;
                    const std::vector<size_t> SUSPICIOUS_SIZES_KB = {
                        18138, 17960, 17959, 17839, 17650, 18153
                    };
                    
                    bool isSuspicious = false;
                    for (const auto& suspiciousSize : SUSPICIOUS_SIZES_KB) {
                        if (sizeInKB == suspiciousSize) {
                            isSuspicious = true;
                            break;
                        }
                    }
                    
                    if (isSuspicious) {
                        std::cout << RED << "    [!] WARNING: Voice node might be used for a hook (" << sizeInKB << " KB)\n" << RESET;
                    }
                    
                    std::cout << "\n" << RESET;

                    log << "[+] Found " << node.type << " (PID: " << process.pid << ")\n";
                    log << "    Voice Node Found at: 0x" << std::hex << process.baseAddress << std::dec << "\n";
                    log << "    Voice Node Size: " << formatVoiceNodeSize(node.size) << "\n";
                    if (isSuspicious) {
                        log << "    [!] WARNING: Voice node might be used for a hook (" << sizeInKB << " KB)\n";
                    }
                    log << "\n";
                    foundDiscordVersions[node.type] = true;
                }
            }
        }

        for (const auto& [version, found] : foundDiscordVersions) {
            if (!found) {
                std::cout << RED << "[!] " << version << " not detected\n" << RESET;
                log << "[!] " << version << " not detected\n\n";
            }
        }
        log.close();

        std::cout << BLUE << "\n[*] Running analysis...\n" << RESET;
        std::cout << "================================================================================\n\n";

        log.open("logs.txt", std::ios::app);
        log << "[*] Hook Analysis Results\n";
        log << "-------------------------------------------------------\n\n";
        log.close();

        std::vector<std::string> versions = { "Discord", "Discord Canary", "Discord PTB" };
        bool hooksFound = false;
        bool anyImGuiFound = false;
        bool anyOpusFound = false;

        for (const auto& version : versions) {
            for (const auto& process : processes) {
                if (process.version == version) {
                    std::cout << GREEN << "[+] Analyzing " << process.version << "...\n\n" << RESET;
                    
                    {
                        std::ofstream log("logs.txt", std::ios::app);
                        log << "[+] Analyzing " << process.version << "...\n\n";
                    }

                    auto result = hookDetector.analyzeModule(process);
                    if (result.foundHooks) hooksFound = true;

                    if (hookDetector.checkForImGui()) {
                        std::cout << RED << "[!] ImGui detected in " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] ImGui detected in " << process.version << "\n";
                        }
                        anyImGuiFound = true;
                    }

                    if (hookDetector.checkForOpusHooks()) {
                        std::cout << RED << "[!] Opus Hooks detected in " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] Opus Hooks detected in " << process.version << "\n";
                        }
                        anyOpusFound = true;
                    }

                    auto audioResult = hookDetector.detectOtherHooks(process.pid);
                    auto hooks = hookDetector.detectAllHooks(process.pid);

                    if (!hooks.empty()) {
                        std::cout << RED << "[!] ReadOnly hooks detected in " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] ReadOnly hooks detected in " << process.version << "\n";
                            for (const auto& hook : hooks) {
                                log << "    Hook at: 0x" << std::hex << hook.moduleBase << " in " << hook.modulePath << "\n";
                            }
                        }
                    }

                    if (!hookDetector.validateVoiceNodeIntegrity(process.path, process.pid)) {
                        std::cout << RED << "[!] Voice node integrity check failed for " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] Voice node integrity check failed for " << process.version << "\n";
                        }
                    }

                    if (hookDetector.detectVTableHooks(process)) {
                        std::cout << RED << "[!] VTable hooks detected in " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] VTable hooks detected in " << process.version << "\n";
                        }
                    }

                    if (hookDetector.detectPageGuardHooks()) {
                        std::cout << RED << "[!] PAGE_GUARD hooks detected in " << process.version << "\n" << RESET;
                        {
                            std::ofstream log("logs.txt", std::ios::app);
                            log << "[!] PAGE_GUARD hooks detected in " << process.version << "\n";
                        }
                    }

                    if (hookDetector.detectLoadLibraryHooking(process.pid)) {
                        std::cout << RED << "[!] LoadLibrary hooking detected in " << process.version << "\n" << RESET;
                    }

                    break;
                }
            }
        }

        log.open("logs.txt", std::ios::app);
        if (!hooksFound && !anyImGuiFound && !anyOpusFound) {
            std::cout << GREEN << "[+] No hooks detected in Discord\n" << RESET;
            log << "[+] No hooks detected in Discord\n\n";
        }
        std::cout << BLUE << "DO NOT CLOSE THE FILE THE CHECKS ARENT FINISHED!\n" << RESET;
        logger.logPrefetch();
        logger.logUsnJournal();
        logger.logTaskList();
        logger.logZombieProcesses();
        logger.logRegistryKeys();
        std::cout << "\033[37m\n================================================================================\n\033[0m";

        log << "\n=======================================================\n";
        log << "                  Process History                       \n";
        log << "=======================================================\n\n";
        log.close();

        processChecker.logProcessHistory();

        log.open("logs.txt", std::ios::app);
        log << "\nScan Completed: " << getCurrentTimestamp() << "\n";
        log << "=======================================================\n\n";
        log.close();

        logger.createZipFile();

        if (std::filesystem::exists("logs.txt")) {
            std::filesystem::remove("logs.txt");
        }

        std::cout << BLUE << "\n[*] All results have been saved to output.zip\n";
        std::cout << "[*] Press Enter to return to menu..." << RESET;
        std::cin.get();
        std::cin.get();
    }
    catch (const std::exception& e) {
        std::cout << RED << "\n[!] Error: " << e.what() << "\n[!] Run as administrator\n" << RESET;
        std::cout << BLUE << "\n[*] Press Enter to return to menu..." << RESET;
        std::cin.get();
    }
}

void runUnNattyBreaker() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_FONT_INFOEX oldFontInfo;
    oldFontInfo.cbSize = sizeof(CONSOLE_FONT_INFOEX);
    GetCurrentConsoleFontEx(hConsole, FALSE, &oldFontInfo);

    try {
        clearScreen();
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

        CONSOLE_FONT_INFOEX fontInfo;
        fontInfo.cbSize = sizeof(fontInfo);
        GetCurrentConsoleFontEx(hConsole, FALSE, &fontInfo);
        wcscpy_s(fontInfo.FaceName, L"Consolas");
        fontInfo.dwFontSize.X = 0;
        fontInfo.dwFontSize.Y = 16;
        SetCurrentConsoleFontEx(hConsole, FALSE, &fontInfo);

        DWORD consoleMode;
        GetConsoleMode(hConsole, &consoleMode);
        SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT);

        TheNiggaCaddle();

        std::atomic<bool> running{ true };
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);

        SHORT startY = csbi.dwCursorPosition.Y;
        std::cout << "\n  Monitoring for Discord processes...\n\n";
        std::cout << "Press 'X' to exit...\n";

        std::string currentDisplayMessage = "";

        std::thread monitorThread([&running, hConsole, startY, &currentDisplayMessage]() {
            while (running) {
                try {
                    IHateNiggers();
                    auto modules = WhyIsAscendSuchABadCoder();

                    COORD pos = { 0, startY + 1 };
                    SetConsoleCursorPosition(hConsole, pos);

                    if (!modules.empty()) {
                        std::string newMessage = "\n  Monitor:\n";
                        for (const auto& module : modules) {
                            newMessage += "  " + std::string(module.processName.begin(), module.processName.end()) +
                                " (PID: " + std::to_string(module.processId) + ")\n";

                            if (TerryDavisMyGoat(module)) {
                                ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                                newMessage += "  → Fixed successfully\n";
                                ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                            }
                        }

                        if (newMessage != currentDisplayMessage) {

                            for (int i = 0; i < 10; i++) {
                                std::cout << "\r" << std::string(80, ' ') << "\n";
                            }
                            SetConsoleCursorPosition(hConsole, pos);

                            ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                            std::cout << newMessage << std::flush;
                            ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                            currentDisplayMessage = newMessage;
                        }
                    }
                    else {
                        SetConsoleCursorPosition(hConsole, pos);
                        ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_INTENSITY);
                        std::string message = "  Waiting for Discord";
                        message += GetDots();
                        std::cout << "\r" << std::string(80, ' ') << "\r" << message << std::flush;
                        ThatsIsForConsoleColorsYouFatFuck(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                        currentDisplayMessage = "";
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                catch (...) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
            });

        while (running) {
            if (_kbhit()) {
                char c = _getch();
                if (toupper(c) == 'X') {
                    running = false;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (monitorThread.joinable()) {
            monitorThread.join();
        }

        SetCurrentConsoleFontEx(hConsole, FALSE, &oldFontInfo);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        clearScreen();

    }
    catch (const std::exception& e) {
        SetCurrentConsoleFontEx(hConsole, FALSE, &oldFontInfo);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        MessageBoxA(NULL, e.what(), "Error", MB_ICONERROR);
    }
    catch (...) {
        SetCurrentConsoleFontEx(hConsole, FALSE, &oldFontInfo);
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        MessageBoxA(NULL, "Unknown error occurred", "Error", MB_ICONERROR);
    }
}

int main() {
    if (!IsElevated()) {
        if (RunAsAdmin()) {
            return 0;
        }
        else {
            MessageBoxA(NULL, "This tool requires administrator privileges to run.\nPlease run as administrator.", "Administrator Rights Required", MB_ICONEXCLAMATION);
            return 1;
        }
    }

    enableConsoleColors();
    SetConsoleOutputCP(CP_UTF8);

    while (true) {
        clearScreen();
        printMainMenu();

        std::cout << "\n    Enter your choice: ";
        char choice = _getch();

        switch (toupper(choice)) {
        case '1':
            runUnnattyDetector();
            break;
        case '2':
            runUnNattyBreaker();
            break;
        case 'X':
            return 0;
        default:
            continue;
        }
    }

    return 0;
}
