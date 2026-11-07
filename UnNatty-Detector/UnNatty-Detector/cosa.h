#pragma once
#ifndef COSA_H
#define COSA_H

#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <shlobj.h>
#include <winreg.h>

class SystemLogger {
private:
    std::wstring logFolder;
    std::wstring userSettingsFolder;
    std::wstring recentDocsFolder;
    std::vector<std::wstring> logFiles;
    void executeCommand(const std::wstring& command, const std::wstring& outputFile);
    void createFolders();
    void dumpRecentFiles();
    void dumpUserSettings();
    void copyFile(const std::wstring& source, const std::wstring& dest);
    std::vector<std::wstring> getRecentFiles();
    std::wstring getTimestamp() const;

public:
    SystemLogger();
    void logPrefetch();
    void logUsnJournal();
    void logTaskList();
    void logFilteredTaskList();
    void logZombieProcesses();
    void logRegistryKeys();
    void createZipFile();
    std::wstring getLogFolderPath() const;
};

#endif
