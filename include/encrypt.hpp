#include <vector>
#include <stdexcept>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

std::vector<unsigned char> SHA512(const std::vector<unsigned char>& data);
std::vector<unsigned char> Encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key512);
std::vector<unsigned char> Decrypt(
    const std::vector<unsigned char>& ciphertextWithTag,
    const std::vector<unsigned char>& key512);
