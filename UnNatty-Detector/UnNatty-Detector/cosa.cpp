#include "cosa.h"
#include <iostream>

SystemLogger::SystemLogger() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {
        logFolder = std::wstring(path) + L"\\Downloads\\System Log";
        userSettingsFolder = logFolder + L"\\UserSettings";
        recentDocsFolder = logFolder + L"\\RecentFiles";
        createFolders();
    }
}

std::wstring SystemLogger::getTimestamp() const {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buffer[100];
    swprintf(buffer, sizeof(buffer) / sizeof(wchar_t),
        L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buffer);
}

void SystemLogger::logPrefetch() {
    std::wstring outputFile = logFolder + L"\\PrefetchLog.txt";
    wchar_t winDir[MAX_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
        std::wstring prefetchPath = std::wstring(winDir) + L"\\Prefetch";
        std::wstring command = L"dir /a /o-d /t:w \"" + prefetchPath + L"\"";
        executeCommand(command, outputFile);
    }
}

std::wstring SystemLogger::getLogFolderPath() const {
    return logFolder;
}

void SystemLogger::createFolders() {
    CreateDirectoryW(logFolder.c_str(), NULL);
    CreateDirectoryW(userSettingsFolder.c_str(), NULL);
    CreateDirectoryW(recentDocsFolder.c_str(), NULL);
}

void SystemLogger::executeCommand(const std::wstring& command, const std::wstring& outputFile) {
    std::wstring fullCommand = command + L" > \"" + outputFile + L"\"";
    _wsystem(fullCommand.c_str());
    logFiles.push_back(outputFile);
}

void SystemLogger::copyFile(const std::wstring& source, const std::wstring& dest) {
    CopyFileW(source.c_str(), dest.c_str(), FALSE);
}

std::vector<std::wstring> SystemLogger::getRecentFiles() {
    std::vector<std::wstring> files;
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, path))) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((std::wstring(path) + L"\\*").c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    files.push_back(std::wstring(path) + L"\\" + findData.cFileName);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    return files;
}

void SystemLogger::dumpRecentFiles() {
    auto recentFiles = getRecentFiles();
    for (const auto& file : recentFiles) {
        std::wstring fileName = std::filesystem::path(file).filename();
        std::wstring destPath = recentDocsFolder + L"\\" + fileName;
        copyFile(file, destPath);
    }
}

void SystemLogger::dumpUserSettings() {
    wchar_t userName[256];
    DWORD size = 256;
    GetUserNameW(userName, &size);

    std::wstring userProfilePath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    std::wstring outputPath = userSettingsFolder + L"\\UserAssist.reg";
    std::wstring command = L"reg export \"HKCU\\" + userProfilePath + L"\" \"" + outputPath + L"\" /y";
    _wsystem(command.c_str());
    logFiles.push_back(outputPath);

    std::wstring bamPath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    std::wstring bamOutput = userSettingsFolder + L"\\BAM_Settings.reg";
    command = L"reg export \"HKLM\\" + bamPath + L"\" \"" + bamOutput + L"\" /y";
    _wsystem(command.c_str());
    logFiles.push_back(bamOutput);

    std::wstring appCompatPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags";
    std::wstring appCompatOutput = userSettingsFolder + L"\\AppCompatFlags.reg";
    command = L"reg export \"HKLM\\" + appCompatPath + L"\" \"" + appCompatOutput + L"\" /y";
    _wsystem(command.c_str());
    logFiles.push_back(appCompatOutput);
}

void SystemLogger::logUsnJournal() {
    std::wstring usnFolder = logFolder + L"\\USNJournal";
    CreateDirectoryW(usnFolder.c_str(), NULL);

    std::wstring outputFile2 = usnFolder + L"\\UsnExecutableActions.txt";
    executeCommand(L"fsutil usn readjournal C: csv | findstr /i \"\.exe \.dll\"", outputFile2);

    std::wstring outputFile3 = usnFolder + L"\\UsnJournalDetails.txt";
    executeCommand(L"fsutil usn queryjournal C:", outputFile3);
}

void SystemLogger::logTaskList() {
    std::wstring taskFolder = logFolder + L"\\Tasks";
    CreateDirectoryW(taskFolder.c_str(), NULL);

    std::wstring outputFile = taskFolder + L"\\TaskList.csv";
    executeCommand(L"tasklist /fo csv /v", outputFile);

    outputFile = taskFolder + L"\\TaskListWithModules.txt";
    executeCommand(L"tasklist /m", outputFile);

    outputFile = taskFolder + L"\\TaskListWithServices.txt";
    executeCommand(L"tasklist /svc", outputFile);
}

void SystemLogger::logFilteredTaskList() {
    std::wstring outputFile = logFolder + L"\\filtered_results.txt";
    std::wstring command = L"tasklist /m | findstr /v /i \"svchost.exe csrss.exe wininit.exe dwm.exe explorer.exe lsass.exe smss.exe system idle\"";
    executeCommand(command, outputFile);
}

void SystemLogger::logZombieProcesses() {
    std::wstring outputFile = logFolder + L"\\ProcessDetails";
    CreateDirectoryW(outputFile.c_str(), NULL);

    executeCommand(L"wmic process get ProcessId,Name,ParentProcessId,SessionId,Status,CreationDate,CommandLine /format:csv > \"" +
        outputFile + L"\\ProcessList.csv\"", outputFile + L"\\ProcessList.csv");

    executeCommand(L"wmic process where \"Status='Not Responding'\" get ProcessId,Name,ParentProcessId,Status /format:csv > \"" +
        outputFile + L"\\ZombieProcesses.csv\"", outputFile + L"\\ZombieProcesses.csv");

    executeCommand(L"wmic process get ExecutablePath,ProcessId,ParentProcessId,CommandLine /format:csv > \"" +
        outputFile + L"\\ProcessPaths.csv\"", outputFile + L"\\ProcessPaths.csv");
}

void SystemLogger::logRegistryKeys() {
    dumpUserSettings();
    dumpRecentFiles();
}

void SystemLogger::createZipFile() {
    std::wstring powershellCommand = L"powershell -command \"Compress-Archive -Path '";
    powershellCommand += logFolder + L"\\*','logs.txt' -DestinationPath 'output.zip' -Force\"";
    _wsystem(powershellCommand.c_str());
}
