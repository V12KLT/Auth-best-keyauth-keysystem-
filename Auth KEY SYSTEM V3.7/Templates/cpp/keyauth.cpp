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
  h ^= h >> 33;
  h *= 0xFF51AFD7ED558CCDULL;
  h ^= h >> 33;
  h *= 0xC4CEB9FE1A85EC53ULL;
  h ^= h >> 33;
  return (uint8_t)(h & 0xFF);
}
template <int N> class ObfString {
  mutable char data_[N];
  uint64_t seed_;
  mutable bool decrypted_ = false;

public:
  constexpr ObfString(const char (&str)[N], uint64_t seed)
      : data_{}, seed_(seed) {
    for (int i = 0; i < N; i++)
      data_[i] = str[i] ^ ct_key(seed, i);
  }
  const char *c_str() const {
    if (!decrypted_) {
      for (int i = 0; i < N; i++)
        data_[i] ^= ct_key(seed_, i);
      decrypted_ = true;
    }
    return data_;
  }
  std::string str() const {
    char tmp[N];
    for (int i = 0; i < N; i++)
      tmp[i] = data_[i] ^ (decrypted_ ? 0 : ct_key(seed_, i));
    return std::string(tmp, N - 1);
  }
  operator std::string() const { return str(); }
};
} // namespace obf_detail

#define OBF(s)                                                                 \
  (obf_detail::ObfString<sizeof(s)>(s, obf_detail::SEED ^ __LINE__))
#define OBF_STR(s) (OBF(s).str())

namespace api_hide {
constexpr uint32_t ct_hash(const char *str) {
  uint32_t hash = 5381;
  while (*str) {
    hash = ((hash << 5) + hash) + (uint8_t)*str;
    str++;
  }
  return hash;
}
inline uint32_t rt_hash(const char *str) {
  uint32_t hash = 5381;
  while (*str) {
    hash = ((hash << 5) + hash) + (uint8_t)*str;
    str++;
  }
  return hash;
}
inline void *resolve_by_hash(HMODULE hMod, uint32_t targetHash) {
  if (!hMod)
    return nullptr;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
  DWORD exportRVA =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  if (!exportRVA)
    return nullptr;
  PIMAGE_EXPORT_DIRECTORY exports =
      (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hMod + exportRVA);
  DWORD *names = (DWORD *)((BYTE *)hMod + exports->AddressOfNames);
  WORD *ordinals = (WORD *)((BYTE *)hMod + exports->AddressOfNameOrdinals);
  DWORD *functions = (DWORD *)((BYTE *)hMod + exports->AddressOfFunctions);
  for (DWORD i = 0; i < exports->NumberOfNames; i++) {
    const char *name = (const char *)((BYTE *)hMod + names[i]);
    if (rt_hash(name) == targetHash)
      return (void *)((BYTE *)hMod + functions[ordinals[i]]);
  }
  return nullptr;
}

typedef BOOL(WINAPI *fn_IsDebuggerPresent)();
typedef BOOL(WINAPI *fn_CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
typedef LONG(NTAPI *fn_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG,
                                                  PULONG);
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
    if (resolved)
      return;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (k32) {
      pIsDebuggerPresent = (fn_IsDebuggerPresent)resolve_by_hash(
          k32, ct_hash("IsDebuggerPresent"));
      pCheckRemoteDebuggerPresent =
          (fn_CheckRemoteDebuggerPresent)resolve_by_hash(
              k32, ct_hash("CheckRemoteDebuggerPresent"));
      pExitProcess =
          (fn_ExitProcess)resolve_by_hash(k32, ct_hash("ExitProcess"));
      pGetCurrentProcess = (fn_GetCurrentProcess)resolve_by_hash(
          k32, ct_hash("GetCurrentProcess"));
      pTerminateProcess = (fn_TerminateProcess)resolve_by_hash(
          k32, ct_hash("TerminateProcess"));
    }
    if (ntdll) {
      pNtQueryInformationProcess =
          (fn_NtQueryInformationProcess)resolve_by_hash(
              ntdll, ct_hash("NtQueryInformationProcess"));
      pNtSetInformationThread = (fn_NtSetInformationThread)resolve_by_hash(
          ntdll, ct_hash("NtSetInformationThread"));
    }
    resolved = true;
  }
};

inline HiddenAPIs &getAPIs() {
  static HiddenAPIs apis;
  if (!apis.resolved)
    apis.resolve();
  return apis;
}

inline void stealth_exit() {
  auto &api = getAPIs();
  if (api.pTerminateProcess && api.pGetCurrentProcess)
    api.pTerminateProcess(api.pGetCurrentProcess(), 0);
  if (api.pExitProcess)
    api.pExitProcess(0);
  *(volatile int *)0 = 0;
}

inline void stealth_hide_thread(HANDLE hThread) {
  auto &api = getAPIs();
  if (api.pNtSetInformationThread)
    api.pNtSetInformationThread(hThread, 0x11, NULL, 0);
}

inline void check_debugger() {
  auto &api = getAPIs();
  if (api.pIsDebuggerPresent && api.pIsDebuggerPresent())
    stealth_exit();
  if (api.pCheckRemoteDebuggerPresent && api.pGetCurrentProcess) {
    BOOL present = FALSE;
    api.pCheckRemoteDebuggerPresent(api.pGetCurrentProcess(), &present);
    if (present)
      stealth_exit();
  }
  if (api.pNtQueryInformationProcess && api.pGetCurrentProcess) {
    ULONG_PTR debugPort = 0;
    api.pNtQueryInformationProcess(api.pGetCurrentProcess(), 7, &debugPort,
                                   sizeof(debugPort), NULL);
    if (debugPort)
      stealth_exit();
  }
}

inline void check_bad_processes() {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  const wchar_t *bad[] = {L"x64dbg.exe",
                          L"x32dbg.exe",
                          L"ollydbg.exe",
                          L"ida.exe",
                          L"ida64.exe",
                          L"idag.exe",
                          L"idag64.exe",
                          L"idaw.exe",
                          L"idaw64.exe",
                          L"wireshark.exe",
                          L"fiddler.exe",
                          L"charles.exe",
                          L"httpdebugger.exe",
                          L"processhacker.exe",
                          L"procmon.exe",
                          L"procexp.exe",
                          L"dnspy.exe",
                          L"de4dot.exe",
                          L"cheatengine-x86_64.exe"};
  if (Process32FirstW(snap, &pe)) {
    do {
      for (auto &b : bad) {
        if (_wcsicmp(pe.szExeFile, b) == 0) {
          CloseHandle(snap);
          stealth_exit();
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
}
} // namespace api_hide

static const unsigned char TOKEN_XOR_KEY[] = {
    0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16,
    0xB9, 0x4F, 0xD2, 0x85, 0x33, 0xFC, 0x47, 0x2A, 0x9E, 0x61, 0xC8,
    0x04, 0x7F, 0xB5, 0x1D, 0xEA, 0x53, 0x96, 0x38, 0xDE, 0x72};
static const int TOKEN_XOR_KEY_LEN = sizeof(TOKEN_XOR_KEY);

inline std::string get_server_host() { return OBF_STR("socket.keyauth.shop"); }
inline int get_server_port() { return 3389; }
inline std::string get_project_id() { return OBF_STR("ENTER_PROJECT_ID_HERE"); }
inline std::string get_token_prefix() { return OBF_STR("AUTH_TOKEN_V2|"); }

static const unsigned char CF_ENC[] = {0x94, 0x7E, 0xB1, 0x6A, 0xD4, 0xF0, 0x5A, 0x3D, 0xDA, 0x3C, 0x55, 0xFA, 0x77, 0x97, 0xB2, 0x71, 0xE5, 0x0F, 0xC4, 0x68, 0xD3, 0x80, 0x29, 0x3F, 0xA0, 0x39, 0x23, 0x89, 0x0A, 0xE7, 0xC0, 0x72, 0xE2, 0x0F, 0xC4, 0x68, 0xA7, 0x87, 0x2C, 0x3F, 0xA7, 0x3E, 0x57, 0x88, 0x09, 0xE3, 0xC6, 0x70, 0x95, 0x0F, 0xB6, 0x6D, 0xD5, 0xF3, 0x2D, 0x39, 0xD2, 0x4B, 0x25, 0x8C, 0x09, 0xEA, 0xB3, 0x75};
static const int CF_ENC_LEN = sizeof(CF_ENC);

static const unsigned char SK_ENC[] = {0xB8, 0xBF, 0xD5, 0x63, 0x73, 0xEC, 0x9C, 0x4B, 0x82, 0x8D, 0xAF, 0x84, 0x32, 0x17, 0x3D, 0x78, 0xF8, 0xCC, 0x41, 0xCB, 0x8A, 0x5D, 0x3B, 0xCD, 0xE9, 0x7C, 0x60, 0x7C, 0x2E, 0x32, 0x0E, 0x33, 0x5B, 0xB5, 0x7C, 0x8D, 0xEE, 0x21, 0x14, 0x56, 0x70, 0x9F, 0xA3, 0x6D, 0x4D, 0x6F, 0x4B, 0xE8, 0x02, 0xC5, 0x6E, 0xE5, 0x7F, 0x33, 0xBC, 0x21, 0x8C, 0x7E, 0xF4, 0xAB, 0x7B, 0x56, 0x1C, 0xA2};
static const int SK_ENC_LEN = sizeof(SK_ENC);

inline bool verifySig(const std::string &data, const std::string &sigHex) {
    if (SK_ENC_LEN <= 1) return true;
    static const unsigned char xk[] = {0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33};
    unsigned char raw[64];
    for (int i = 0; i < SK_ENC_LEN && i < 64; i++) raw[i] = SK_ENC[i] ^ xk[i % 16];

    struct { ULONG Magic; ULONG cbKey; } blobHdr = {0x31534345, 32};
    unsigned char blob[8 + 64];
    memcpy(blob, &blobHdr, 8);
    memcpy(blob + 8, raw, 64);

    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    bool result = false;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0))) return true;
    if (!NT_SUCCESS(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob, sizeof(blob), 0))) { BCryptCloseAlgorithmProvider(hAlg, 0); return true; }

    BCRYPT_ALG_HANDLE hSha = NULL;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hSha, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    unsigned char hash[32]; ULONG hashLen = 0;
    if (!NT_SUCCESS(BCryptCreateHash(hSha, &hHash, NULL, 0, NULL, 0, 0))) { BCryptCloseAlgorithmProvider(hSha, 0); goto cleanup; }
    BCryptHashData(hHash, (PUCHAR)data.c_str(), (ULONG)data.size(), 0);
    BCryptFinishHash(hHash, hash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hSha, 0);

    { unsigned char sig[64];
      if (sigHex.size() != 128) goto cleanup;
      for (int i = 0; i < 64; i++) {
        char h1 = sigHex[i*2], h2 = sigHex[i*2+1];
        auto hv = [](char c) -> int { return c >= '0' && c <= '9' ? c-'0' : c >= 'a' && c <= 'f' ? 10+c-'a' : c >= 'A' && c <= 'F' ? 10+c-'A' : -1; };
        int v1 = hv(h1), v2 = hv(h2); if (v1 < 0 || v2 < 0) goto cleanup;
        sig[i] = (unsigned char)(v1 * 16 + v2);
      }
      result = NT_SUCCESS(BCryptVerifySignature(hKey, NULL, hash, 32, sig, 64, 0));
    }
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

inline std::string sha256(const std::string &str);

inline std::string decodeCfEnc() {
    if (CF_ENC_LEN <= 1) return "";
    static const unsigned char xk[] = {0xA7, 0x3B, 0xF2, 0x5E, 0x91, 0xC4, 0x68, 0x0D, 0xE3, 0x7A, 0x16, 0xB9, 0x4F, 0xD2, 0x85, 0x33};
    std::string result(CF_ENC_LEN, '\0');
    for (int i = 0; i < CF_ENC_LEN; i++) result[i] = CF_ENC[i] ^ xk[i % 16];
    return result;
}

inline bool verifyCertPin(CtxtHandle &hCtx) {
    std::string expected = decodeCfEnc();
    if (expected.empty()) return true;

    PCCERT_CONTEXT pCert = NULL;
    SECURITY_STATUS status = QueryContextAttributes(&hCtx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert);
    if (status != SEC_E_OK || !pCert) return false;

    std::string certHash = sha256(std::string((char *)pCert->pbCertEncoded, pCert->cbCertEncoded));
    CertFreeCertificateContext(pCert);

    std::string normalizedExpected;
    for (char c : expected) normalizedExpected += (char)toupper(c);
    std::string normalizedHash;
    for (char c : certHash) normalizedHash += (char)toupper(c);

    return normalizedHash == normalizedExpected;
}


inline std::vector<unsigned char> g_encryptedToken;
inline uint32_t g_tokenCanary = 0;
inline bool g_tokenPresent = false;

inline void xorEncryptDecrypt(const std::string &input,
                              std::vector<unsigned char> &output) {
  output.resize(input.size());
  for (size_t i = 0; i < input.size(); i++)
    output[i] = (unsigned char)input[i] ^ TOKEN_XOR_KEY[i % TOKEN_XOR_KEY_LEN];
}

inline std::string xorDecrypt(const std::vector<unsigned char> &input) {
  std::string output(input.size(), '\0');
  for (size_t i = 0; i < input.size(); i++)
    output[i] = (char)(input[i] ^ TOKEN_XOR_KEY[i % TOKEN_XOR_KEY_LEN]);
  return output;
}

inline uint32_t computeTokenCanary(const std::vector<unsigned char> &data) {
  uint32_t hash = 0x811C9DC5;
  for (auto b : data) {
    hash ^= b;
    hash *= 0x01000193;
  }
  return hash ^ 0xDEADBEEF;
}

inline void storeToken(const std::string &token) {
  xorEncryptDecrypt(token, g_encryptedToken);
  g_tokenCanary = computeTokenCanary(g_encryptedToken);
  g_tokenPresent = true;
}

inline std::string getDecryptedToken() {
  if (!g_tokenPresent || g_encryptedToken.empty())
    return "";
  if (computeTokenCanary(g_encryptedToken) != g_tokenCanary) {
    api_hide::stealth_exit();
    return "";
  }
  return xorDecrypt(g_encryptedToken);
}

inline bool isTokenValid() {
  std::string token = getDecryptedToken();
  if (token.empty())
    return false;
  if (token.substr(0, 14) != get_token_prefix())
    return false;
  if (token.length() <= 22)
    return false;
  return true;
}

inline std::string getHWID() {
  auto runWmic = [](const char *cls, const char *prop) -> std::string {
    std::string cmd = std::string("wmic path ") + cls + " get " + prop;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
      return "";
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
      CloseHandle(hReadPipe);
      CloseHandle(hWritePipe);
      return "";
    }
    CloseHandle(hWritePipe);
    WaitForSingleObject(pi.hProcess, 3000);
    char buf[1024] = {};
    DWORD bytesRead = 0;
    ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, NULL);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::string out(buf, bytesRead);
    size_t nl = out.find('\n');
    if (nl == std::string::npos)
      return "";
    std::string val = out.substr(nl + 1);
    size_t start = val.find_first_not_of(" \t\r\n");
    size_t end = val.find_last_not_of(" \t\r\n");
    if (start == std::string::npos)
      return "";
    return val.substr(start, end - start + 1);
  };
  std::string cpuId = runWmic("Win32_Processor", "ProcessorId");
  std::string mbSerial = runWmic("Win32_BaseBoard", "SerialNumber");
  std::string biosSerial = runWmic("Win32_BIOS", "SerialNumber");
  std::string combined = cpuId + "|" + mbSerial + "|" + biosSerial;
  // Forward declare sha256 or use it directly if defined above
  extern std::string sha256(const std::string &str);
  return sha256(combined);
}

inline std::string sha256(const std::string &str) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  if (!NT_SUCCESS(
          BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    return "";
  DWORD cbHashObject, cbData;
  BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject,
                    sizeof(DWORD), &cbData, 0);
  std::vector<BYTE> pbHashObject(cbHashObject);
  if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject.data(),
                                   cbHashObject, NULL, 0, 0))) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return "";
  }
  BCryptHashData(hHash, (PBYTE)str.c_str(), (ULONG)str.length(), 0);
  DWORD cbHash;
  BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD),
                    &cbData, 0);
  std::vector<BYTE> pbHash(cbHash);
  BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);
  std::stringstream ss;
  for (BYTE b : pbHash)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return ss.str();
}

inline std::string hmacSha256(const std::string &key, const std::string &data) {
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
          &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
    return "";
  DWORD cbHashObject, cbData;
  BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject,
                    sizeof(DWORD), &cbData, 0);
  std::vector<BYTE> pbHashObject(cbHashObject);
  if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject.data(),
                                   cbHashObject, (PBYTE)key.c_str(),
                                   (ULONG)key.length(), 0))) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return "";
  }
  BCryptHashData(hHash, (PBYTE)data.c_str(), (ULONG)data.length(), 0);
  DWORD cbHash;
  BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD),
                    &cbData, 0);
  std::vector<BYTE> pbHash(cbHash);
  BCryptFinishHash(hHash, pbHash.data(), cbHash, 0);
  std::stringstream ss;
  for (BYTE b : pbHash)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return ss.str();
}

class MiniSsl {
  SOCKET sock;
  CredHandle hCred;
  CtxtHandle hCtx;
  bool connected = false;

public:
  MiniSsl(SOCKET s) : sock(s) {
    memset(&hCred, 0, sizeof(hCred));
    memset(&hCtx, 0, sizeof(hCtx));
  }
  ~MiniSsl() {
    if (connected) {
      DeleteSecurityContext(&hCtx);
      FreeCredentialsHandle(&hCred);
    }
  }
  CtxtHandle &getCtx() { return hCtx; }

  bool Connect(const std::string &hostname) {
    SCHANNEL_CRED credData = {0};
    credData.dwVersion = SCHANNEL_CRED_VERSION;
    TimeStamp tsExpiry;
    if (AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A,
                                  SECPKG_CRED_OUTBOUND, NULL, &credData, NULL,
                                  NULL, &hCred, &tsExpiry) != SEC_E_OK)
      return false;
    DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                        ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    DWORD dwSSPIOutFlags = 0;
    SecBufferDesc outBufferDesc;
    SecBuffer outBuffers[1];
    outBuffers[0].pvBuffer = NULL;
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].cbBuffer = 0;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = outBuffers;
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    SECURITY_STATUS status = InitializeSecurityContextA(
        &hCred, NULL, (SEC_CHAR *)hostname.c_str(), dwSSPIFlags, 0, 0, NULL, 0,
        &hCtx, &outBufferDesc, &dwSSPIOutFlags, &tsExpiry);
    if (status != SEC_I_CONTINUE_NEEDED)
      return false;
    if (outBuffers[0].pvBuffer && outBuffers[0].cbBuffer) {
      send(sock, (char *)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
      FreeContextBuffer(outBuffers[0].pvBuffer);
    }
    while (status == SEC_I_CONTINUE_NEEDED ||
           status == SEC_E_INCOMPLETE_MESSAGE ||
           status == SEC_I_INCOMPLETE_CREDENTIALS) {
      std::vector<char> remoteData(8192);
      int received = recv(sock, remoteData.data(), (int)remoteData.size(), 0);
      if (received <= 0)
        return false;
      SecBufferDesc inBufferDesc;
      SecBuffer inBuffers[2];
      inBuffers[0].pvBuffer = remoteData.data();
      inBuffers[0].cbBuffer = received;
      inBuffers[0].BufferType = SECBUFFER_TOKEN;
      inBuffers[1].pvBuffer = NULL;
      inBuffers[1].cbBuffer = 0;
      inBuffers[1].BufferType = SECBUFFER_EMPTY;
      inBufferDesc.cBuffers = 2;
      inBufferDesc.pBuffers = inBuffers;
      inBufferDesc.ulVersion = SECBUFFER_VERSION;
      outBuffers[0].pvBuffer = NULL;
      outBuffers[0].BufferType = SECBUFFER_TOKEN;
      outBuffers[0].cbBuffer = 0;
      outBufferDesc.cBuffers = 1;
      outBufferDesc.pBuffers = outBuffers;
      outBufferDesc.ulVersion = SECBUFFER_VERSION;
      status = InitializeSecurityContextA(
          &hCred, &hCtx, (SEC_CHAR *)hostname.c_str(), dwSSPIFlags, 0, 0,
          &inBufferDesc, 0, NULL, &outBufferDesc, &dwSSPIOutFlags, &tsExpiry);
      if (status == SEC_E_INCOMPLETE_MESSAGE)
        return false;
      if (outBuffers[0].pvBuffer && outBuffers[0].cbBuffer) {
        send(sock, (char *)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
        FreeContextBuffer(outBuffers[0].pvBuffer);
      }
      if (status == SEC_E_OK) {
        connected = true;
        return true;
      }
    }
    return false;
  }

  int Write(const void *data, int len) {
    if (!connected)
      return -1;
    SecPkgContext_StreamSizes Sizes;
    QueryContextAttributes(&hCtx, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    int totalLen = Sizes.cbHeader + len + Sizes.cbTrailer;
    std::vector<char> buffer(totalLen);
    SecBufferDesc Message;
    SecBuffer Buffers[4];
    Buffers[0].pvBuffer = buffer.data();
    Buffers[0].cbBuffer = Sizes.cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    Buffers[1].pvBuffer = buffer.data() + Sizes.cbHeader;
    Buffers[1].cbBuffer = len;
    Buffers[1].BufferType = SECBUFFER_DATA;
    memcpy(Buffers[1].pvBuffer, data, len);
    Buffers[2].pvBuffer = buffer.data() + Sizes.cbHeader + len;
    Buffers[2].cbBuffer = Sizes.cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    Buffers[3].BufferType = SECBUFFER_EMPTY;
    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;
    if (FAILED(EncryptMessage(&hCtx, 0, &Message, 0)))
      return -1;
    return send(sock, buffer.data(),
                Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                0);
  }

  int Read(char *buffer, int maxLen) {
    if (!connected || maxLen <= 0)
      return -1;
    std::vector<char> encryptedData(16384);
    int received =
        recv(sock, encryptedData.data(), (int)encryptedData.size(), 0);
    if (received <= 0)
      return received;
    SecBufferDesc Message;
    SecBuffer Buffers[4];
    Buffers[0].pvBuffer = encryptedData.data();
    Buffers[0].cbBuffer = received;
    Buffers[0].BufferType = SECBUFFER_DATA;
    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;
    Message.ulVersion = SECBUFFER_VERSION;
    Message.cBuffers = 4;
    Message.pBuffers = Buffers;
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
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    out_data = OBF_STR("Failed");
    return "";
  }

  struct addrinfo hints = {0}, *result = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  std::string srvHost = get_server_host();
  if (getaddrinfo(srvHost.c_str(), std::to_string(get_server_port()).c_str(),
                  &hints, &result) != 0) {
    out_data = OBF_STR("Failed");
    WSACleanup();
    return "";
  }

  SOCKET sockfd =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (sockfd == INVALID_SOCKET) {
    out_data = OBF_STR("Failed");
    freeaddrinfo(result);
    WSACleanup();
    return "";
  }

  if (connect(sockfd, result->ai_addr, (int)result->ai_addrlen) ==
      SOCKET_ERROR) {
    out_data = OBF_STR("Failed");
    closesocket(sockfd);
    freeaddrinfo(result);
    WSACleanup();
    return "";
  }
  freeaddrinfo(result);

  MiniSsl ssl(sockfd);
  if (!ssl.Connect(srvHost)) {
    out_data = OBF_STR("Failed");
    closesocket(sockfd);
    WSACleanup();
    return "";
  }

  if (!verifyCertPin(ssl.getCtx())) {
    out_data = OBF_STR("Cert pin failed");
    closesocket(sockfd);
    WSACleanup();
    return "";
  }

  ssl.Write("2", 1);
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  std::string authData = get_project_id() + "|" + key + "|" + getHWID();
  ssl.Write(authData.c_str(), (int)authData.length());

  char buffer[1024] = {0};
  int bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
  if (bytesRead <= 0) {
    out_data = OBF_STR("Failed");
    closesocket(sockfd);
    WSACleanup();
    return "";
  }

  std::string response(buffer, bytesRead);
  std::string token;

  if (response.find("CHALLENGE|") == 0) {
    size_t firstPipe = response.find('|');
    size_t secondPipe = response.find('|', firstPipe + 1);
    if (firstPipe != std::string::npos && secondPipe != std::string::npos) {
      std::string challengeId =
          response.substr(firstPipe + 1, secondPipe - firstPipe - 1);
      std::string challenge = response.substr(secondPipe + 1);
      std::string signature = hmacSha256(key, challenge);
      std::string responseMsg = "RESPONSE|" + challengeId + "|" + signature;
      ssl.Write(responseMsg.c_str(), (int)responseMsg.length());
      memset(buffer, 0, sizeof(buffer));
      bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
      if (bytesRead <= 0) {
        out_data = OBF_STR("Failed");
        closesocket(sockfd);
        WSACleanup();
        return "";
      }
      std::string finalResult(buffer, bytesRead);
      if (finalResult.find("ACCESS|") == 0) {
        size_t p1 = finalResult.find('|');
          size_t p2 = finalResult.find('|', p1 + 1);
          size_t p3 = finalResult.find('|', p2 + 1);
          if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) {
            out_data = OBF_STR("Refused");
          } else {
            std::string accessToken = finalResult.substr(p1 + 1, p2 - p1 - 1);
            std::string serverProof = finalResult.substr(p2 + 1, p3 - p2 - 1);
            std::string authSig = finalResult.substr(p3 + 1);
            std::string expectedProof = hmacSha256(key, challenge + "|" + accessToken);
            if (serverProof != expectedProof || !verifySig(challenge + "|" + accessToken, authSig)) {
              out_data = OBF_STR("Refused");
            } else {
              token = get_token_prefix() + accessToken + "|" + hmacSha256(key, accessToken);
              out_data = accessToken;
            }
          }
      } else {
        out_data = OBF_STR("Refused");
      }
    } else {
      out_data = OBF_STR("Failed");
    }
  } else {
    out_data = OBF_STR("Refused");
  }

  closesocket(sockfd);
  WSACleanup();
  if (!token.empty())
    storeToken(token);
  return token;
}

inline std::string g_sessionKey;
inline std::string g_sessionHWID;
inline bool g_sessionActive = false;

inline bool verify_session(const std::string &key) {
  if (!isTokenValid()) {
    api_hide::stealth_exit();
    return false;
  }

  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    return false;
  struct addrinfo hints = {0}, *result = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  std::string vsrvHost = get_server_host();
  if (getaddrinfo(vsrvHost.c_str(), std::to_string(get_server_port()).c_str(),
                  &hints, &result) != 0) {
    WSACleanup();
    return false;
  }
  SOCKET sockfd =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (sockfd == INVALID_SOCKET) {
    freeaddrinfo(result);
    WSACleanup();
    return false;
  }
  DWORD timeout = 10000;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
             sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
             sizeof(timeout));
  if (connect(sockfd, result->ai_addr, (int)result->ai_addrlen) ==
      SOCKET_ERROR) {
    closesocket(sockfd);
    freeaddrinfo(result);
    WSACleanup();
    return false;
  }
  freeaddrinfo(result);
  MiniSsl ssl(sockfd);
  if (!ssl.Connect(vsrvHost)) {
    closesocket(sockfd);
    WSACleanup();
    return false;
  }

  if (!verifyCertPin(ssl.getCtx())) {
    closesocket(sockfd);
    WSACleanup();
    api_hide::stealth_exit();
    return false;
  }
  ssl.Write("3", 1);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  std::string hwid = g_sessionHWID.empty() ? getHWID() : g_sessionHWID;
  std::string verifyData = get_project_id() + "|" + key + "|" + hwid;
  ssl.Write(verifyData.c_str(), (int)verifyData.length());
  char buffer[1024] = {0};
  int bytesRead = ssl.Read(buffer, sizeof(buffer) - 1);
  closesocket(sockfd);
  WSACleanup();
  if (bytesRead <= 0)
    return false;
  std::string response(buffer, bytesRead);
  if (response.find("VALID|") != 0)
    return false;
  size_t p1 = response.find('|');
  size_t p2 = response.find('|', p1 + 1);
  size_t p3 = response.find('|', p2 + 1);
  size_t p4 = response.find('|', p3 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos || p4 == std::string::npos)
    return false;
  std::string remaining = response.substr(p2 + 1, p3 - p2 - 1);
  std::string verifyProof = response.substr(p3 + 1, p4 - p3 - 1);
  std::string sigStr = response.substr(p4 + 1);
  std::string vfyData = "VERIFY:" + get_project_id() + ":" + remaining;
  std::string expected = hmacSha256(key, vfyData);
  return verifyProof == expected && verifySig(vfyData, sigStr);
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
      if (!g_sessionActive)
        break;
      api_hide::check_debugger();
      api_hide::check_bad_processes();
      if (verify_session(key)) {
        consecutiveFailures = 0;
      } else {
        consecutiveFailures++;
        if (consecutiveFailures >= 3)
          api_hide::stealth_exit();
      }
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
