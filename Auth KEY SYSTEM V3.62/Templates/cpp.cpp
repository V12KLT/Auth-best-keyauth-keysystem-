#pragma once
#ifndef _KEYAUTH_CLIENT_HPP_
#define _KEYAUTH_CLIENT_HPP_

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SECURITY_WIN32
#include <bcrypt.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace obf_detail {
constexpr uint64_t ct_seed() {
    uint64_t h = 0x5E3A1F9C7B4D2E6FULL;
    const char t[] = __TIME__;
    for (int i = 0; i < 8; i++) {
        h ^= (uint64_t)t[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}
constexpr uint64_t SEED = ct_seed();
constexpr uint8_t ct_key(uint64_t seed, int index) {
    uint64_t h = seed ^ ((uint64_t)index * 0x9E3779B97F4A7C15ULL);
    h ^= h >> 33; h *= 0xFF51AFD7ED558CCDULL;
    h ^= h >> 33; h *= 0xC4CEB9FE1A85EC53ULL;
    h ^= h >> 33;
    return (uint8_t)(h & 0xFF);
}
template <int N> class ObfString {
    mutable char data_[N];
    uint64_t seed_;
    mutable bool decrypted_ = false;
public:
    constexpr ObfString(const char (&str)[N], uint64_t seed) : data_{}, seed_(seed) {
        for (int i = 0; i < N; i++) data_[i] = str[i] ^ ct_key(seed, i);
    }
    const char *c_str() const {
        if (!decrypted_) {
            for (int i = 0; i < N; i++) data_[i] ^= ct_key(seed_, i);
            decrypted_ = true;
        }
        return data_;
    }
    std::string str() const {
        char tmp[N];
        for (int i = 0; i < N; i++) tmp[i] = data_[i] ^ (decrypted_ ? 0 : ct_key(seed_, i));
        return std::string(tmp, N - 1);
    }
    operator std::string() const { return str(); }
};
}

#define OBF(s) (obf_detail::ObfString<sizeof(s)>(s, obf_detail::SEED ^ __LINE__))
#define OBF_STR(s) (OBF(s).str())

namespace api_hide {
constexpr uint32_t ct_hash(const char *str) {
    uint32_t hash = 5381;
    while (*str) { hash = ((hash << 5) + hash) + (uint8_t)*str; str++; }
    return hash;
}
inline uint32_t rt_hash(const char *str) {
    uint32_t hash = 5381;
    while (*str) { hash = ((hash << 5) + hash) + (uint8_t)*str; str++; }
    return hash;
}
inline void *resolve_by_hash(HMODULE hMod, uint32_t targetHash) {
    if (!hMod) return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) return nullptr;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hMod + exportRVA);
    DWORD *names = (DWORD *)((BYTE *)hMod + exports->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hMod + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hMod + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE *)hMod + names[i]);
        if (rt_hash(name) == targetHash) return (void *)((BYTE *)hMod + functions[ordinals[i]]);
    }
    return nullptr;
}

typedef BOOL(WINAPI *fn_IsDebuggerPresent)();
typedef BOOL(WINAPI *fn_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef LONG(NTAPI *fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI *fn_NtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
typedef void(WINAPI *fn_ExitProcess)(UINT);
typedef HANDLE(WINAPI *fn_GetCurrentProcess)();
typedef BOOL(WINAPI *fn_TerminateProcess)(HANDLE, UINT);

struct HiddenAPIs {
    fn_IsDebuggerPresent pIsDebuggerPresent = nullptr;
    fn_CheckRemoteDebuggerPresent pCheckRemoteDebuggerPresent = nullptr;
    fn_NtQueryInformationProcess pNtQueryInformationProcess = nullptr;
    fn_NtSetInformationThread pNtSetInformationThread = nullptr;
    fn_ExitProcess pExitProcess = nullptr;
    fn_GetCurrentProcess pGetCurrentProcess = nullptr;
    fn_TerminateProcess pTerminateProcess = nullptr;
    bool resolved = false;
    void resolve() {
        if (resolved) return;
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (k32) {
            pIsDebuggerPresent = (fn_IsDebuggerPresent)resolve_by_hash(k32, ct_hash("IsDebuggerPresent"));
            pCheckRemoteDebuggerPresent = (fn_CheckRemoteDebuggerPresent)resolve_by_hash(k32, ct_hash("CheckRemoteDebuggerPresent"));
            pExitProcess = (fn_ExitProcess)resolve_by_hash(k32, ct_hash("ExitProcess"));
            pGetCurrentProcess = (fn_GetCurrentProcess)resolve_by_hash(k32, ct_hash("GetCurrentProcess"));
            pTerminateProcess = (fn_TerminateProcess)resolve_by_hash(k32, ct_hash("TerminateProcess"));
        }
        if (ntdll) {
            pNtQueryInformationProcess = (fn_NtQueryInformationProcess)resolve_by_hash(ntdll, ct_hash("NtQueryInformationProcess"));
            pNtSetInformationThread = (fn_NtSetInformationThread)resolve_by_hash(ntdll, ct_hash("NtSetInformationThread"));
        }
        resolved = true;
    }
};

inline HiddenAPIs &getAPIs() { static HiddenAPIs apis; if (!apis.resolved) apis.resolve(); return apis; }

inline void stealth_exit() {
    auto &api = getAPIs();
    if (api.pTerminateProcess && api.pGetCurrentProcess) api.pTerminateProcess(api.pGetCurrentProcess(), 0);
    if (api.pExitProcess) api.pExitProcess(0);
    *(volatile int *)0 = 0;
}

inline void stealth_hide_thread(HANDLE hThread) {
    auto &api = getAPIs();
    if (api.pNtSetInformationThread) api.pNtSetInformationThread(hThread, 0x11, NULL, 0);
}

inline void check_debugger() {
    auto &api = getAPIs();
    if (api.pIsDebuggerPresent && api.pIsDebuggerPresent()) stealth_exit();
    if (api.pCheckRemoteDebuggerPresent && api.pGetCurrentProcess) {
        BOOL present = FALSE;
        api.pCheckRemoteDebuggerPresent(api.pGetCurrentProcess(), &present);
        if (present) stealth_exit();
    }
    if (api.pNtQueryInformationProcess && api.pGetCurrentProcess) {
        ULONG_PTR debugPort = 0;
        api.pNtQueryInformationProcess(api.pGetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
        if (debugPort) stealth_exit();
    }
}

inline void check_bad_processes() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    const wchar_t* bad[] = {L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe",
        L"idag.exe", L"idag64.exe", L"idaw.exe", L"idaw64.exe", L"wireshark.exe", L"fiddler.exe",
        L"charles.exe", L"httpdebugger.exe", L"processhacker.exe", L"procmon.exe", L"procexp.exe",
        L"dnspy.exe", L"de4dot.exe", L"cheatengine-x86_64.exe"};
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto &b : bad) {
                if (_wcsicmp(pe.szExeFile, b) == 0) { CloseHandle(snap); stealth_exit(); }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}
}

static const unsigned char TOKEN_XOR_KEY[] = {
    0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16,
    0xB9, 0x4F, 0xD2, 0x85, 0x33, 0xFC, 0x47, 0x2A, 0x9E, 0x61, 0xC8,
    0x04, 0x7F, 0xB5, 0x1D, 0xEA, 0x53, 0x96, 0x38, 0xDE, 0x72};
static const int TOKEN_XOR_KEY_LEN = sizeof(TOKEN_XOR_KEY);

inline std::string get_server_host() { return OBF_STR("socket.keyauth.shop"); }
inline int get_server_port() { return 3389; }
inline std::string get_project_id() { return OBF_STR("ENTER_PROJECT_ID_HERE"); }
inline std::string get_token_prefix() { return OBF_STR("AUTH_TOKEN_V2|"); }

inline std::vector<unsigned char> g_encryptedToken;
inline uint32_t g_tokenCanary = 0;
inline bool g_tokenPresent = false;

inline void xorEncryptDecrypt(const std::string &input, std::vector<unsigned char> &output) {
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); i++) output[i] = (unsigned char)input[i] ^ TOKEN_XOR_KEY[i % TOKEN_XOR_KEY_LEN];
}

inline std::string xorDecrypt(const std::vector<unsigned char> &input) {
    std::string output(input.size(), '\0');
    for (size_t i = 0; i < input.size(); i++) output[i] = (char)(input[i] ^ TOKEN_XOR_KEY[i % TOKEN_XOR_KEY_LEN]);
    return output;
}

inline uint32_t computeTokenCanary(const std::vector<unsigned char> &data) {
    uint32_t hash = 0x811C9DC5;
    for (auto b : data) { hash ^= b; hash *= 0x01000193; }
    return hash ^ 0xDEADBEEF;
}

inline void storeToken(const std::string &token) {
    xorEncryptDecrypt(token, g_encryptedToken);
    g_tokenCanary = computeTokenCanary(g_encryptedToken);
    g_tokenPresent = true;
}

inline std::string getDecryptedToken() {
    if (!g_tokenPresent || g_encryptedToken.empty()) return "";
    if (computeTokenCanary(g_encryptedToken) != g_tokenCanary) { api_hide::stealth_exit(); return ""; }
    return xorDecrypt(g_encryptedToken);
}

inline bool isTokenValid() {
    std::string token = getDecryptedToken();
    if (token.empty()) return false;
    if (token.substr(0, 14) != get_token_prefix()) return false;
    if (token.length() <= 22) return false;
    return true;
}

inline std::string getHWID() {
    HKEY hKey;
    std::string regPath = OBF_STR("SOFTWARE\\Microsoft\\Cryptography");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char value[256]; DWORD size = sizeof(value);
        std::string valueName = OBF_STR("MachineGuid");
        if (RegQueryValueExA(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return std::string(value);
        }
        RegCloseKey(hKey);
    }
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) return std::string(hostname);
    return OBF_STR("UNKNOWN");
}

inline std::string sha256(const std::string &str) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return "";
    DWORD cbHashObject, cbData;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    std::vector<BYTE> pbHashObject(cbHashObject);
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject.data(), cbHashObject, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return "";
    }
    BCryptHashData(hHash, (PBYTE)str.c_str(), (ULONG)str.length(), 0);
    DWORD cbHash;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    std::vector<BYTE> pbHash(cbHash);
    BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);
    std::stringstream ss;
    for (BYTE b : pbHash) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return ss.str();
}

inline std::string hmacSha256(const std::string &key, const std::string &data) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return "";
    DWORD cbHashObject, cbData;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    std::vector<BYTE> pbHashObject(cbHashObject);
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject.data(), cbHashObject, (PBYTE)key.c_str(), (ULONG)key.length(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return "";
    }
    BCryptHashData(hHash, (PBYTE)data.c_str(), (ULONG)data.length(), 0);
    DWORD cbHash;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    std::vector<BYTE> pbHash(cbHash);
    BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);
    std::stringstream ss;
    for (BYTE b : pbHash) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return ss.str();
}

class MiniSsl {
    SOCKET sock;
    CredHandle hCred;
    CtxtHandle hCtx;
    bool connected = false;
public:
    MiniSsl(SOCKET s) : sock(s) { memset(&hCred, 0, sizeof(hCred)); memset(&hCtx, 0, sizeof(hCtx)); }
    ~MiniSsl() { if (connected) { DeleteSecurityContext(&hCtx); FreeCredentialsHandle(&hCred); } }

    bool Connect(const std::string &hostname) {
        SCHANNEL_CRED credData = {0}; credData.dwVersion = SCHANNEL_CRED_VERSION;
        TimeStamp tsExpiry;
        if (AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &credData, NULL, NULL, &hCred, &tsExpiry) != SEC_E_OK) return false;
        DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
        DWORD dwSSPIOutFlags = 0;
        SecBufferDesc outBufferDesc; SecBuffer outBuffers[1];
        outBuffers[0].pvBuffer = NULL; outBuffers[0].BufferType = SECBUFFER_TOKEN; outBuffers[0].cbBuffer = 0;
        outBufferDesc.cBuffers = 1; outBufferDesc.pBuffers = outBuffers; outBufferDesc.ulVersion = SECBUFFER_VERSION;
        SECURITY_STATUS status = InitializeSecurityContextA(&hCred, NULL, (SEC_CHAR *)hostname.c_str(), dwSSPIFlags, 0, 0, NULL, 0, &hCtx, &outBufferDesc, &dwSSPIOutFlags, &tsExpiry);
        if (status != SEC_I_CONTINUE_NEEDED) return false;
        if (outBuffers[0].pvBuffer && outBuffers[0].cbBuffer) { send(sock, (char *)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0); FreeContextBuffer(outBuffers[0].pvBuffer); }
        while (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_I_INCOMPLETE_CREDENTIALS) {
            std::vector<char> remoteData(8192);
            int received = recv(sock, remoteData.data(), (int)remoteData.size(), 0);
            if (received <= 0) return false;
            SecBufferDesc inBufferDesc; SecBuffer inBuffers[2];
            inBuffers[0].pvBuffer = remoteData.data(); inBuffers[0].cbBuffer = received; inBuffers[0].BufferType = SECBUFFER_TOKEN;
            inBuffers[1].pvBuffer = NULL; inBuffers[1].cbBuffer = 0; inBuffers[1].BufferType = SECBUFFER_EMPTY;
            inBufferDesc.cBuffers = 2; inBufferDesc.pBuffers = inBuffers; inBufferDesc.ulVersion = SECBUFFER_VERSION;
            outBuffers[0].pvBuffer = NULL; outBuffers[0].BufferType = SECBUFFER_TOKEN; outBuffers[0].cbBuffer = 0;
            outBufferDesc.cBuffers = 1; outBufferDesc.pBuffers = outBuffers; outBufferDesc.ulVersion = SECBUFFER_VERSION;
            status = InitializeSecurityContextA(&hCred, &hCtx, (SEC_CHAR *)hostname.c_str(), dwSSPIFlags, 0, 0, &inBufferDesc, 0, NULL, &outBufferDesc, &dwSSPIOutFlags, &tsExpiry);
            if (status == SEC_E_INCOMPLETE_MESSAGE) return false;
            if (outBuffers[0].pvBuffer && outBuffers[0].cbBuffer) { send(sock, (char *)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0); FreeContextBuffer(outBuffers[0].pvBuffer); }
            if (status == SEC_E_OK) { connected = true; return true; }
        }
        return false;
    }

    int Write(const void *data, int len) {
        if (!connected) return -1;
        SecPkgContext_StreamSizes Sizes; QueryContextAttributes(&hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
        int totalLen = Sizes.cbHeader + len + Sizes.cbTrailer;
        std::vector<char> buffer(totalLen);
        SecBufferDesc Message; SecBuffer Buffers[4];
        Buffers[0].pvBuffer = buffer.data(); Buffers[0].cbBuffer = Sizes.cbHeader; Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        Buffers[1].pvBuffer = buffer.data() + Sizes.cbHeader; Buffers[1].cbBuffer = len; Buffers[1].BufferType = SECBUFFER_DATA;
        memcpy(Buffers[1].pvBuffer, data, len);
        Buffers[2].pvBuffer = buffer.data() + Sizes.cbHeader + len; Buffers[2].cbBuffer = Sizes.cbTrailer; Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        Buffers[3].BufferType = SECBUFFER_EMPTY;
        Message.ulVersion = SECBUFFER_VERSION; Message.cBuffers = 4; Message.pBuffers = Buffers;
        if (FAILED(EncryptMessage(&hCtx, 0, &Message, 0))) return -1;
        return send(sock, buffer.data(), Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);
    }

    int Read(char *buffer, int maxLen) {
        if (!connected || maxLen <= 0) return -1;
        std::vector<char> encryptedData(16384);
        int received = recv(sock, encryptedData.data(), (int)encryptedData.size(), 0);
        if (received <= 0) return received;
        SecBufferDesc Message; SecBuffer Buffers[4];
        Buffers[0].pvBuffer = encryptedData.data(); Buffers[0].cbBuffer = received; Buffers[0].BufferType = SECBUFFER_DATA;
        Buffers[1].BufferType = SECBUFFER_EMPTY; Buffers[2].BufferType = SECBUFFER_EMPTY; Buffers[3].BufferType = SECBUFFER_EMPTY;
        Message.ulVersion = SECBUFFER_VERSION; Message.cBuffers = 4; Message.pBuffers = Buffers;
        SECURITY_STATUS status = DecryptMessage(&hCtx, &Message, 0, NULL);
        if (status == SEC_E_OK || status == SEC_I_RENEGOTIATE) {
            for (int i = 0; i < 4; i++) {
                if (Buffers[i].BufferType == SECBUFFER_DATA) {
                    int toCopy = (std::min)((int)Buffers[i].cbBuffer, maxLen);
                    memcpy(buffer, Buffers[i].pvBuffer, toCopy);
                    return toCopy;
                }
            }
        }
        return -1;
    }
};

inline std::string authenticate(const std::string &key, std::string &out_data) {
    api_hide::check_debugger();
    api_hide::check_bad_processes();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) { out_data = OBF_STR("Failed"); return ""; }

    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    std::string srvHost = get_server_host();
    if (getaddrinfo(srvHost.c_str(), std::to_string(get_server_port()).c_str(), &hints, &result) != 0) {
        out_data = OBF_STR("Failed"); WSACleanup(); return "";
    }

    SOCKET sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == INVALID_SOCKET) { out_data = OBF_STR("Failed"); freeaddrinfo(result); WSACleanup(); return ""; }

    if (connect(sockfd, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        out_data = OBF_STR("Failed"); closesocket(sockfd); freeaddrinfo(result); WSACleanup(); return "";
    }
    freeaddrinfo(result);

    MiniSsl ssl(sockfd);
    if (!ssl.Connect(srvHost)) { out_data = OBF_STR("Failed"); closesocket(sockfd); WSACleanup(); return ""; }

    ssl.Write("2", 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::string authData = get_project_id() + "|" + key + "|" + getHWID();
    ssl.Write(authData.c_str(), (int)authData.length());

    char buffer[1024] = {0};
    int bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
    if (bytesRead <= 0) { out_data = OBF_STR("Failed"); closesocket(sockfd); WSACleanup(); return ""; }

    std::string response(buffer, bytesRead);
    std::string token;

    if (response.find("CHALLENGE|") == 0) {
        size_t firstPipe = response.find('|');
        size_t secondPipe = response.find('|', firstPipe + 1);
        if (firstPipe != std::string::npos && secondPipe != std::string::npos) {
            std::string challengeId = response.substr(firstPipe + 1, secondPipe - firstPipe - 1);
            std::string challenge = response.substr(secondPipe + 1);
            std::string signature = hmacSha256(key, challenge);
            std::string responseMsg = "RESPONSE|" + challengeId + "|" + signature;
            ssl.Write(responseMsg.c_str(), (int)responseMsg.length());
            memset(buffer, 0, sizeof(buffer));
            bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
            if (bytesRead <= 0) { out_data = OBF_STR("Failed"); closesocket(sockfd); WSACleanup(); return ""; }
            std::string finalResult(buffer, bytesRead);
            if (finalResult.find("ACCESS|") == 0) {
                std::string serverData = finalResult.substr(7);
                token = get_token_prefix() + serverData + "|" + hmacSha256(key, serverData);
                out_data = serverData;
            } else { out_data = OBF_STR("Refused"); }
        } else { out_data = OBF_STR("Failed"); }
    } else if (response.find("ACCESS|") == 0) {
        std::string serverData = response.substr(7);
        token = get_token_prefix() + serverData + "|" + hmacSha256(key, serverData);
        out_data = serverData;
    } else { out_data = OBF_STR("Refused"); }

    closesocket(sockfd); WSACleanup();
    if (!token.empty()) storeToken(token);
    return token;
}

inline std::string g_sessionKey;
inline std::string g_sessionHWID;
inline bool g_sessionActive = false;

inline bool verify_session(const std::string &key) {
    if (!isTokenValid()) { api_hide::stealth_exit(); return false; }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    std::string vsrvHost = get_server_host();
    if (getaddrinfo(vsrvHost.c_str(), std::to_string(get_server_port()).c_str(), &hints, &result) != 0) { WSACleanup(); return false; }
    SOCKET sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd == INVALID_SOCKET) { freeaddrinfo(result); WSACleanup(); return false; }
    DWORD timeout = 10000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    if (connect(sockfd, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sockfd); freeaddrinfo(result); WSACleanup(); return false;
    }
    freeaddrinfo(result);
    MiniSsl ssl(sockfd);
    if (!ssl.Connect(vsrvHost)) { closesocket(sockfd); WSACleanup(); return false; }
    ssl.Write("3", 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::string hwid = g_sessionHWID.empty() ? getHWID() : g_sessionHWID;
    std::string verifyData = get_project_id() + "|" + key + "|" + hwid;
    ssl.Write(verifyData.c_str(), (int)verifyData.length());
    char buffer[1024] = {0};
    int bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
    closesocket(sockfd); WSACleanup();
    if (bytesRead <= 0) return false;
    std::string response(buffer, bytesRead);
    return response.find("VALID") == 0;
}

inline void StartSessionValidationThread(const std::string &key) {
    g_sessionKey = key;
    g_sessionHWID = getHWID();
    g_sessionActive = true;
    std::thread([key]() {
        api_hide::stealth_hide_thread(GetCurrentThread());
        int consecutiveFailures = 0;
        while (g_sessionActive) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (!g_sessionActive) break;
            api_hide::check_debugger();
            api_hide::check_bad_processes();
            if (verify_session(key)) { consecutiveFailures = 0; }
            else { consecutiveFailures++; if (consecutiveFailures >= 3) api_hide::stealth_exit(); }
        }
    }).detach();
}

#ifndef KEYAUTH_HEADER_ONLY
int main() {
    api_hide::check_debugger();
    api_hide::check_bad_processes();

    std::string key;
    std::cout << "Enter your license key: ";
    std::getline(std::cin, key);

    std::string out_data;
    std::string token = authenticate(key, out_data);

    if (!token.empty()) {
        std::cout << "Authenticated." << std::endl;
        StartSessionValidationThread(key);
    } else {
        return 1;
    }

    return 0;
}
#endif

#endif