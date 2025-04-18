#include "crypto_guard_ctx.h"
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    CRYPT_TYPE encrypt;                       // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() : cipher_ctx_(EVP_CIPHER_CTX_new()), md_ctx_(EVP_MD_CTX_new()) {}
    ~Impl() {}

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(Impl &&) noexcept = delete;
    Impl &operator=(Impl &&) noexcept = delete;

    std::string CalculateChecksum(std::iostream &inStream) {
        // max chunk size to read
        constexpr size_t BUFFER_SIZE = 65'536;

        int in_size = GetIOstreamSize(inStream);
        std::vector<char> in_vec((in_size > BUFFER_SIZE) ? BUFFER_SIZE : in_size);

        if (!EVP_DigestInit_ex2(md_ctx_.get(), EVP_sha256(), NULL)) {
            throw std::runtime_error("Cannot init digest");
        }

        while (inStream.good() && !inStream.eof()) {
            int read_size = (in_size > BUFFER_SIZE) ? BUFFER_SIZE : in_size;

            inStream.read(in_vec.data(), read_size);
            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                if (!EVP_DigestUpdate(md_ctx_.get(), reinterpret_cast<void *>(in_vec.data()), in_size)) {
                    throw std::runtime_error("Cannot update digest");
                }
            } else {
                break;
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_length = 0;
        if (!EVP_DigestFinal(md_ctx_.get(), hash, &hash_length)) {
            throw std::runtime_error("Cannot final digest");
        }

        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (unsigned int i = 0; i < hash_length; ++i) {
            ss << std::setw(2) << static_cast<int>(hash[i]);  // set every byte as hex
        }

        return ss.str();
    }

    void CryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, CRYPT_TYPE cryptType) {
        if (&inStream == &outStream) {
            throw std::runtime_error("Input and output streams are equal");
        }

        if (!inStream.good() || !outStream.good()) {
            throw std::runtime_error("Input or output streams are invalid");
        }

        constexpr size_t BUFFER_SIZE = 1024;
        int out_Len;

        int in_size = GetIOstreamSize(inStream);
        std::vector<unsigned char> in_vec((in_size > BUFFER_SIZE) ? BUFFER_SIZE : in_size);

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = cryptType;

        std::vector<unsigned char> out_vec(in_vec.size() + EVP_CIPHER_block_size(params.cipher));

        if (!EVP_CipherInit_ex(cipher_ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               static_cast<int>(params.encrypt))) {
            throw std::runtime_error("Cannot init cypher");
        }

        while (inStream.good() && !inStream.eof()) {
            int read_size = (in_vec.size() > BUFFER_SIZE) ? BUFFER_SIZE : in_vec.size();

            inStream.read(reinterpret_cast<char *>(in_vec.data()), read_size);
            std::streamsize bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                if (!EVP_CipherUpdate(cipher_ctx_.get(), out_vec.data(), &out_Len, in_vec.data(),
                                      static_cast<int>(bytesRead))) {
                    throw std::runtime_error("Cannot update cypher");
                }
            } else {
                break;
            }
            outStream.write(reinterpret_cast<const char *>(out_vec.data()), out_Len);
            if (!outStream.good()) {
                throw std::runtime_error("Output stream is invalid");
            }
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(cipher_ctx_.get(), out_vec.data(), &out_Len);
        outStream.write(reinterpret_cast<const char *>(out_vec.data()), out_Len);

        if (!outStream.good()) {
            throw std::runtime_error("Output stream is invalid");
        }
    }

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error("Failed to create a key from password");
        }

        return params;
    }

    int GetIOstreamSize(std::iostream &stream) {
        auto originalPos = stream.tellg();
        // Seek to the end to get the total size
        stream.seekg(0, std::ios_base::end);
        int in_size = stream.tellg();
        stream.seekg(originalPos);

        return in_size;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> cipher_ctx_;

    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })> md_ctx_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->CryptFile(inStream, outStream, password, CRYPT_TYPE::ENCRYPT);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->CryptFile(inStream, outStream, password, CRYPT_TYPE::DECRYPT);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
