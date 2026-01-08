#include "../include/encrypt.hpp"

/*
 * 1. SHA-512 hash function
 */
std::vector<unsigned char> SHA512(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> hash(SHA512_DIGEST_LENGTH);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA512 computation failed");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

/*
 * 2. Encrypt using AES-256-GCM with a 512-bit key
 */
std::vector<unsigned char> Encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key512)
{
    if (key512.size() != 64)
        throw std::invalid_argument("Key must be exactly 512 bits (64 bytes)");

    // Split key
    const unsigned char* aesKey = key512.data();
    const unsigned char* ivMaterial = key512.data() + 32;

    // Derive 96-bit IV from second half of key
    unsigned char iv[12];
    std::memcpy(iv, key512.data() + 32, 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aesKey, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption init failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), plaintext.size());

    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag, tag + 16);

    return ciphertext;
}

/*
 * 3. Decrypt using AES-256-GCM with a 512-bit key
 */
std::vector<unsigned char> Decrypt(
    const std::vector<unsigned char>& ciphertextWithTag,
    const std::vector<unsigned char>& key512)
{
    constexpr size_t FAILURE_SIZE = 208;

    // Early sanity check
    if (ciphertextWithTag.size() < 16 || key512.size() != 64) {
        return std::vector<unsigned char>(FAILURE_SIZE, '\0');
    }

    unsigned char iv[12];
    std::memcpy(iv, key512.data() + 32, 12);

    size_t ctLen = ciphertextWithTag.size() - 16;
    const unsigned char* tag = ciphertextWithTag.data() + ctLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return std::vector<unsigned char>(FAILURE_SIZE, '\0');
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key512.data(), iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>(FAILURE_SIZE, '\0');
    }

    std::vector<unsigned char> plaintext(ctLen);
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertextWithTag.data(), ctLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::vector<unsigned char>(FAILURE_SIZE, '\0');
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);

    int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok != 1) {
        // Authentication failed: wrong key or tampered data
        return std::vector<unsigned char>(FAILURE_SIZE, '\0');
    }

    return plaintext;
}
