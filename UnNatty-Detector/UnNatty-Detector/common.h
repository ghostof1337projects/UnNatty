#pragma once
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <map>
#include <set>
#include <sstream>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma execution_character_set("utf-8")
#define UNICODE
#define _UNICODE
#pragma optimize("gs", on)
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/SECTION:.text,RWE")

#define STRINGIZE(x) #x
#define STRIP_STRINGS(x) ([]{ constexpr char s[] = STRINGIZE(x); return s; }())

#define PROCESS_VM_READ 0x0010

#ifdef _WIN32
#define BLUE "\033[94m"
#define RED "\033[91m"
#define GREEN "\033[92m"
#define RESET "\033[0m"
#else
#define BLUE ""
#define RED ""
#define GREEN ""
#define RESET ""
#endif

struct ProcessInfo {
    DWORD pid;
    ULONGLONG baseAddress;
    std::string path;
    std::string version;
};

struct ProcessHistory {
    std::string path;
    FILETIME timestamp;
};

void logToFile(const std::string& filename, const std::string& content);
void printSeparator();
std::string fileTimeToString(const FILETIME& ft);
std::string bytesToHexString(const std::vector<uint8_t>& bytes);
std::string getCurrentTimestamp();
