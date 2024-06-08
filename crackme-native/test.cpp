#include <windows.h>
#include <wincrypt.h>
#include <iostream>

#pragma comment(lib, "Advapi32.lib")

void PrintHash(BYTE* hash, DWORD hashLen) {
    for (DWORD i = 0; i < hashLen; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    const char* data = "22152bf604ed0ae4345345345e799c3c6433454355b88e693543534545937483234534534a9a345345eb161d47fc6b534534560123daad";
    DWORD dataLen = strlen(data);

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // SHA-256 produces a 32-byte hash
    DWORD hashLen = 32;

    // Acquire a cryptographic provider context handle
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    // Compute the cryptographic hash of the data
    if (!CryptHashData(hHash, (BYTE*)data, dataLen, 0)) {
        std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    // Retrieve the hash value
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        std::cerr << "CryptGetHashParam failed: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 1;
    }

    // Print the hash
    PrintHash(hash, hashLen);

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return 0;
}
