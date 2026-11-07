#pragma once
#include <windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <unordered_set>
#include <utility>
#include "common.h"

struct HookPattern {
    std::vector<uint8_t> pattern;
    std::string name;
};

struct HookDetectionResult {
    bool foundHooks;
    std::string sectionName;
    uint64_t offset;
    std::string hookType;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> modifiedBytes;
};

struct HookInfo {
    std::string modulePath;
    uintptr_t moduleBase;
};

struct AudioHookResult {
    bool hasAudioHooks;
    std::vector<std::pair<std::string, std::string>> detectedHooks;
    std::string detectionType;
};

struct ReadOnlyHookResult {
    bool hasReadOnlyHooks;
    std::vector<std::pair<std::string, std::string>> readingProcesses;
    std::vector<std::pair<std::string, std::string>> suspiciousPatterns;
    std::vector<std::pair<std::string, std::string>> violations;
};

class HookDetector {
public:
    HookDetector();

    HookDetectionResult analyzeModule(const ProcessInfo& processInfo);
    void writeHookDetails(const std::string& logFilePath, const HookDetectionResult& result, bool isHook);
    bool validateNodeIntegrity(const std::string& nodePath);
    bool detectIATHooks(HMODULE module);
    bool detectVTableHooks(const ProcessInfo& processInfo);
    bool detectInlineHooks(HMODULE module);
    bool detectPageGuardHooks();
    bool forceLoadOriginalNode(const std::string& nodePath);
    bool checkForMinHook();// will prob implement later
    AudioHookResult detectOtherHooks(DWORD processId);
    bool checkForOpusHooks();
    bool checkForImGui();
    void scanModuleForSuspiciousPatterns(const std::vector<uint8_t>& moduleData, const std::string& moduleName);
    void scanModulePatterns(HMODULE module, DWORD processId);
    std::vector<HookInfo> detectAllHooks(DWORD processId);
    bool validateVoiceNodeIntegrity(const std::string& voiceNodePath, DWORD processId);
    bool detectLoadLibraryHooking(DWORD processId);

private:
    const std::vector<std::string> EXTENDED_MINHOOK_SIGNATURES = {
        "minhook.h",
        "mh_initialize",
        "mh_createhook",
        "mh_enablehook",
        "mh_disablehook",
        "mh_removehook",
        "mh_applyqueued",
        "MH_CreateHook",
        "MH_EnableHook",
        "MH_DisableHook",
        "MH_RemoveHook",
        "MH_STATUS",
        "MH_OK",
        "MH_UNKNOWN",
        "DetourAttach",
        "DetourDetach",
        "trampoline",
        "Trampoline"
    };

    const std::vector<std::string> EXTENDED_IMGUI_SIGNATURES = {
        "dear imgui",
        "imgui_impl_",
        "ImGui::Begin",
        "ImGui::End",
        "ImGui::Render",
        "imgui_internal.h",
    };

    const std::vector<std::string> AUDIO_SIGNATURES = {
        "IAudioClient",
        "IAudioRenderClient",
        "IAudioCaptureClient",
        "AudioHook",
        "SoundHook",
        "VoiceHook",
        "VoiceCodec",
        "Stereo",
        "Volume",
        "AudioInterceptor"
    };// will prob implement later

    const std::vector<std::string> opusSignatures = {
    "opus_encoder",
    "opus_decoder",
    "opus_encode",
    "opus_decode",
    "opusfile",
    "opus_custom",
    "opus_multistream",
    "opus_repacketizer",
    "opus_packet",
    "opus_lib",
    "opus_projects",
    "libopus",
    "opus_projection",
    "opus_encode_float",
    "opus_decode_float",
    "opus_pcm",
    "opus_stream",
    "opus_voice",
    "opus_get_version_string"

    };
    const std::vector<std::vector<uint8_t>> MINHOOK_HEX_PATTERNS = {
        {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0},
    };// will prob implement later

    const std::vector<std::vector<uint8_t>> AUDIO_HEX_PATTERNS = {
        {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0},
        {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00},

    };// will prob implement later

    std::vector<HookPattern> HOOK_PATTERNS = {
        {{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}, "JMP_QWORD_PTR"},
        {{0xE9, 0x00, 0x00, 0x00, 0x00}, "JMP_RELATIVE"},
        {{0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0}, "ABSOLUTE_JMP"}
    };// will prob implement later

    bool isAddressHooked(void* address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(address, &mbi, sizeof(mbi))) return true;
        return (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) != 0;
    }

    bool isValidHookPattern(const std::vector<uint8_t>& buffer, size_t offset, const std::vector<uint8_t>& pattern) {
        if (offset + pattern.size() > buffer.size()) return false;
        return std::equal(pattern.begin(), pattern.end(), buffer.begin() + offset);
    }

    bool isExecutableMemory(MEMORY_BASIC_INFORMATION& mbi) {
        return (mbi.State == MEM_COMMIT) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
    }
};
