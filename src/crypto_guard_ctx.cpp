#include "crypto_guard_ctx.h"
#include <cstddef>
#include <iostream>
#include <openssl/evp.h>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
  static const size_t KEY_SIZE = 32;            // AES-256 key size
  static const size_t IV_SIZE = 16;             // AES block size (IV length)
  const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Cipher algorithm

  int encrypt;                             // 1 for encryption, 0 for decryption
  std::array<unsigned char, KEY_SIZE> key; // Encryption key
  std::array<unsigned char, IV_SIZE> iv;   // Initialization vector
};

struct CryptoGuardCtx::Impl {
  Impl() : evp_ctx_(EVP_CIPHER_CTX_new()) {}
  ~Impl() {}
  std::string CalculateChecksum(std::iostream &inStream) {
    return "NOT_IMPLEMENTED";
  }

  bool EncryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {
    if (!inStream.good() || !outStream.good()) {
      return false;
    }

    auto params = CreateChiperParamsFromPassword(password);

    EVP_CipherInit_ex(evp_ctx_.get(), params.cipher, nullptr, params.key.data(),
                      params.iv.data(), params.encrypt);

    auto originalPos = inStream.tellg();
    // Seek to the end to get the total size
    inStream.seekg(0, std::ios_base::end);
    int in_size = inStream.tellg();
    inStream.seekg(originalPos);
    std::vector<unsigned char> in_vec((in_size / 16) * 16 +
                                      ((in_size % 16) ? 16 : 0));
    inStream.read((char *)in_vec.data(), in_size);

    unsigned char out_buf[16];
    int out_Len;
    int in_shift = 0;

    while (in_shift < in_size) {
      // Обрабатываем оставшиеся символы
      EVP_CipherUpdate(evp_ctx_.get(), out_buf, &out_Len,
                       &in_vec.data()[in_shift], static_cast<int>(16));
      outStream.write((const char *)out_buf, out_Len);
      in_shift += 16;
      if (!inStream.good() || !outStream.good()) {
        return false;
      }
    }

    // Заканчиваем работу с cipher
    EVP_CipherFinal_ex(evp_ctx_.get(), out_buf, &out_Len);
    outStream.write((const char *)out_buf, out_Len);
    if (!inStream.good() || !outStream.good()) {
      return false;
    }

    return true;
  }

  bool DecryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0; // decryption

    EVP_CipherInit_ex(evp_ctx_.get(), params.cipher, nullptr, params.key.data(),
                      params.iv.data(), params.encrypt);

    auto originalPos = inStream.tellg();
    // Seek to the end to get the total size
    inStream.seekg(0, std::ios_base::end);
    int in_size = inStream.tellg();
    inStream.seekg(originalPos);

    std::vector<unsigned char> ciphertext(in_size);
    inStream.read((char *)ciphertext.data(), in_size);

    std::vector<unsigned char> plaintext(
        in_size +
        EVP_CIPHER_block_size(params.cipher)); // Allocate space for plaintext

    int len = 0;
    int plaintext_len = 0;

    // Decrypt the ciphertext
    if (EVP_CipherUpdate(evp_ctx_.get(), plaintext.data(), &len,
                         ciphertext.data(), ciphertext.size()) != 1) {
      return false;
    }
    outStream.write((const char *)plaintext.data(), plaintext_len);
    plaintext_len += len;

    // Finalize the decryption
    if (EVP_CipherFinal_ex(evp_ctx_.get(), plaintext.data() + plaintext_len,
                           &len) != 1) {
      return false;
    }
    outStream.write((const char *)plaintext.data(), plaintext_len);

    return true;
  }

  AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4',
                                                   '5', '6', '7', '8'};

    int result =
        EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                       reinterpret_cast<const unsigned char *>(password.data()),
                       password.size(), 1, params.key.data(), params.iv.data());

    if (result == 0) {
      throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
  }

  std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) {
                    EVP_CIPHER_CTX_free(ctx);
                  })>
      evp_ctx_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  if (pImpl_->EncryptFile(inStream, outStream, password) == false) {
    throw std::logic_error("Encryption error occurred");
  }
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  if (pImpl_->DecryptFile(inStream, outStream, password) == false) {
    throw std::logic_error("Decryption error occurred");
  }
}

} // namespace CryptoGuard
