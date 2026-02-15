#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <sysinfoapi.h>
#else
#include <fstream>
#include <cstdlib>
#endif

const std::string SERVER_HOST = "socket.keyauth.shop";
const int SERVER_PORT = 3389;
const std::string PROJECT_ID = "ENTER_PROJECT_ID_HERE";

std::string getHWID() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(value);
        }
        RegCloseKey(hKey);
    }
    
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#else
    std::ifstream file("/sys/class/dmi/id/product_uuid");
    if (file.is_open()) {
        std::string uuid;
        std::getline(file, uuid);
        file.close();
        if (!uuid.empty()) {
            return uuid;
        }
    }
    
    file.open("/etc/machine-id");
    if (file.is_open()) {
        std::string uuid;
        std::getline(file, uuid);
        file.close();
        if (!uuid.empty()) {
            return uuid;
        }
    }
    
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#endif
    return "UNKNOWN";
}

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string hmacSha256(const std::string& key, const std::string& data) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key.c_str(), key.length(), 
                  (unsigned char*)data.c_str(), data.length(), NULL, NULL);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}

bool authenticate(const std::string& key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "[KeyAuth] Unable to create SSL context" << std::endl;
        return false;
    }
    
    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    struct hostent* host = gethostbyname(SERVER_HOST.c_str());
    if (!host) {
        std::cerr << "[KeyAuth] Unable to resolve hostname" << std::endl;
        SSL_CTX_free(ctx);
        return false;
    }
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "[KeyAuth] Unable to create socket" << std::endl;
        SSL_CTX_free(ctx);
        return false;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[KeyAuth] Connection failed" << std::endl;
        close(sockfd);
        SSL_CTX_free(ctx);
        return false;
    }
    
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "[KeyAuth] SSL connection failed" << std::endl;
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return false;
    }
    
    SSL_write(ssl, "2", 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::string authData = PROJECT_ID + "|" + key + "|" + getHWID();
    SSL_write(ssl, authData.c_str(), authData.length());
    
    char buffer[1024] = {0};
    int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    std::string response(buffer, bytesRead);
    
    bool result = false;
    
    if (response.find("CHALLENGE|") == 0) {
        size_t firstPipe = response.find('|');
        size_t secondPipe = response.find('|', firstPipe + 1);
        
        if (firstPipe != std::string::npos && secondPipe != std::string::npos) {
            std::string challengeId = response.substr(firstPipe + 1, secondPipe - firstPipe - 1);
            std::string challenge = response.substr(secondPipe + 1);
            
            std::string signature = hmacSha256(key, challenge);
            
            std::string responseMsg = "RESPONSE|" + challengeId + "|" + signature;
            SSL_write(ssl, responseMsg.c_str(), responseMsg.length());
            
            memset(buffer, 0, sizeof(buffer));
            bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            std::string finalResult(buffer, bytesRead);
            
            if (finalResult.find("ACCESS|") == 0) {
                std::cout << "[KeyAuth] Authenticated." << std::endl;
                result = true;
            } else {
                std::cout << "[KeyAuth] Refused: " << finalResult << std::endl;
                result = false;
            }
        } else {
            std::cout << "[KeyAuth] Invalid challenge format" << std::endl;
            result = false;
        }
    } else if (response.find("ACCESS|") == 0) {
        std::cout << "[KeyAuth] Authenticated." << std::endl;
        result = true;
    } else {
        std::cout << "[KeyAuth] Refused: " << response << std::endl;
        result = false;
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    
    return result;
}

int main() {
    std::string key;
    std::cout << "Enter your license key: ";
    std::getline(std::cin, key);
    
    if (authenticate(key)) {
        // Your program code here
    } else {
        return 1;
    }
    
    return 0;
}