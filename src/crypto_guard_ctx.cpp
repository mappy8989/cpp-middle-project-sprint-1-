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
  static const size_t KEY_SIZE = 32;            // AES-256 key size
  static const size_t IV_SIZE = 16;             // AES block size (IV length)
  const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Cipher algorithm

  int encrypt;                             // 1 for encryption, 0 for decryption
  std::array<unsigned char, KEY_SIZE> key; // Encryption key
  std::array<unsigned char, IV_SIZE> iv;   // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
  Impl(CryptoGuardCtx *outer)
      : cipher_ctx_(EVP_CIPHER_CTX_new()), md_ctx_(EVP_MD_CTX_new()) {}
  ~Impl() {}

  Impl(const Impl &) = delete;
  Impl &operator=(const Impl &) = delete;

  Impl(Impl &&) noexcept = delete;
  Impl &operator=(Impl &&) noexcept = delete;

  std::string CalculateChecksum(std::iostream &inStream) {
    int in_size = GetIOstreamSize(inStream);
    std::vector<unsigned char> in_vec(in_size);
    inStream.read((char *)in_vec.data(), in_size);

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    EVP_DigestInit(md_ctx_.get(), EVP_sha256());
    if (!EVP_DigestInit_ex2(md_ctx_.get(), EVP_sha256(), NULL)) {
      outer_->ERR_get_error("Cannot init digest");
    }

    if (!EVP_DigestUpdate(md_ctx_.get(),
                          reinterpret_cast<void *>(in_vec.data()), in_size)) {
      outer_->ERR_get_error("Cannot update digest");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;
    if (!EVP_DigestFinal(md_ctx_.get(), hash, &hash_length)) {
      outer_->ERR_get_error("Cannot final digest");
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < hash_length; ++i) {
      ss << std::setw(2) << static_cast<int>(hash[i]); // set every byte as hex
    }

    return ss.str();
  }

  bool EncryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {
    if (!inStream.good() || !outStream.good()) {
      return false;
    }

    auto params = CreateChiperParamsFromPassword(password);

    EVP_CipherInit_ex(cipher_ctx_.get(), params.cipher, nullptr,
                      params.key.data(), params.iv.data(), params.encrypt);

    int in_size = GetIOstreamSize(inStream);
    // have to create buffer with 16-bytes padding
    std::vector<unsigned char> in_vec((in_size / 16) * 16 +
                                      ((in_size % 16) ? 16 : 0));
    inStream.read(reinterpret_cast<char *>(in_vec.data()), in_size);

    unsigned char out_buf[16];
    int out_Len;
    int in_shift = 0;

    while (in_shift < in_size) {
      // Обрабатываем оставшиеся символы
      EVP_CipherUpdate(cipher_ctx_.get(), out_buf, &out_Len,
                       &in_vec.data()[in_shift], static_cast<int>(16));
      outStream.write(reinterpret_cast<const char *>(out_buf), out_Len);
      in_shift += 16;
      if (!inStream.good() || !outStream.good()) {
        return false;
      }
    }

    // Заканчиваем работу с cipher
    EVP_CipherFinal_ex(cipher_ctx_.get(), out_buf, &out_Len);
    outStream.write(reinterpret_cast<const char *>(out_buf), out_Len);
    if (!inStream.good() || !outStream.good()) {
      return false;
    }

    return true;
  }

  bool DecryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0; // decryption

    EVP_CipherInit_ex(cipher_ctx_.get(), params.cipher, nullptr,
                      params.key.data(), params.iv.data(), params.encrypt);

    int in_size = GetIOstreamSize(inStream);
    std::vector<unsigned char> ciphertext(in_size);
    inStream.read(reinterpret_cast<char *>(ciphertext.data()), in_size);

    std::vector<unsigned char> plaintext(
        in_size +
        EVP_CIPHER_block_size(params.cipher)); // Allocate space for plaintext

    int len = 0;
    int plaintext_len = 0;

    // Decrypt the ciphertext
    if (EVP_CipherUpdate(cipher_ctx_.get(), plaintext.data(), &len,
                         ciphertext.data(), ciphertext.size()) != 1) {
      return false;
    }
    outStream.write(reinterpret_cast<const char *>(plaintext.data()),
                    plaintext_len);
    plaintext_len += len;

    // Finalize the decryption
    if (EVP_CipherFinal_ex(cipher_ctx_.get(), plaintext.data() + plaintext_len,
                           &len) != 1) {
      return false;
    }
    outStream.write(reinterpret_cast<const char *>(plaintext.data()),
                    plaintext_len);

    return true;
  }

private:
  AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4',
                                                   '5', '6', '7', '8'};

    int result =
        EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                       reinterpret_cast<const unsigned char *>(password.data()),
                       password.size(), 1, params.key.data(), params.iv.data());

    if (result == 0) {
      outer_->ERR_get_error("Failed to create a key from password");
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

  std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) {
                    EVP_CIPHER_CTX_free(ctx);
                  })>
      cipher_ctx_;

  std::unique_ptr<EVP_MD_CTX,
                  decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>
      md_ctx_;

  CryptoGuardCtx *outer_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>(this)) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  if (pImpl_->EncryptFile(inStream, outStream, password) == false) {
    ERR_get_error("Encryption error occurred");
  }
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  if (pImpl_->DecryptFile(inStream, outStream, password) == false) {
    ERR_get_error("Decryption error occurred");
  }
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
  return pImpl_->CalculateChecksum(inStream);
}

} // namespace CryptoGuard
