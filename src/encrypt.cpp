#include "../include/encrypt.hpp"

#include <openssl/kdf.h>

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


static void HKDF_SHA512(
    const unsigned char* ikm, size_t ikm_len,
    const unsigned char* info, size_t info_len,
    unsigned char* out, size_t out_len)
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("HKDF ctx failed");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0 ||
        EVP_PKEY_derive(pctx, out, &out_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF derive failed");
    }

    EVP_PKEY_CTX_free(pctx);
}

std::vector<unsigned char> Encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key512)
{
    if (key512.size() != 64)
        throw std::invalid_argument("Key must be 64 bytes");

    unsigned char aesKey[32];

    // Use ALL 512 bits via HKDF
    HKDF_SHA512(
        key512.data(), key512.size(),
        reinterpret_cast<const unsigned char*>("AES-256-GCM key"),
        15,
        aesKey, sizeof(aesKey));

    // Generate random IV (96 bits, per NIST)
    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        throw std::runtime_error("IV generation failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("CTX failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aesKey, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }

    int total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }

    total += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(total);

    // Output = IV || ciphertext || tag
    std::vector<unsigned char> out;
    out.insert(out.end(), iv, iv + sizeof(iv));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag, tag + sizeof(tag));

    return out;
}

std::vector<unsigned char> Decrypt(
    const std::vector<unsigned char>& ciphertextWithIvAndTag,
    const std::vector<unsigned char>& key512)
{
    constexpr size_t IV_LEN      = 12;
    constexpr size_t TAG_LEN     = 16;
    constexpr size_t FAILURE_LEN = 208;

    auto failure = []() {
        return std::vector<unsigned char>(FAILURE_LEN, '\0');
    };

    if (key512.size() != 64 ||
        ciphertextWithIvAndTag.size() < IV_LEN + TAG_LEN)
    {
        return failure();
    }

    // Parse input
    const unsigned char* iv  = ciphertextWithIvAndTag.data();
    size_t ctLen = ciphertextWithIvAndTag.size() - IV_LEN - TAG_LEN;
    const unsigned char* ct  = iv + IV_LEN;
    const unsigned char* tag = ct + ctLen;

    unsigned char aesKey[32];

    // Use ALL 512 bits via HKDF
    try {
        HKDF_SHA512(
            key512.data(), key512.size(),
            reinterpret_cast<const unsigned char*>("AES-256-GCM key"),
            15,
            aesKey, sizeof(aesKey));
    } catch (...) {
        return failure();
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return failure();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, aesKey, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return failure();
    }

    std::vector<unsigned char> plaintext(ctLen);
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct, ctLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return failure();
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            TAG_LEN, (void*)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return failure();
    }

    int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok != 1)
        return failure();

    return plaintext;
}
