#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>

struct AesCipherParams {
  static const size_t KEY_SIZE = 32;            // AES-256 key size
  static const size_t IV_SIZE = 16;             // AES block size (IV length)
  const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Cipher algorithm

  int encrypt;                             // 1 for encryption, 0 for decryption
  std::array<unsigned char, KEY_SIZE> key; // Encryption key
  std::array<unsigned char, IV_SIZE> iv;   // Initialization vector
};

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

int main(int argc, char *argv[]) {
  try {
    OpenSSL_add_all_algorithms();

    CryptoGuard::ProgramOptions options;
    options.Parse(argc, argv);

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
    switch (options.GetCommand()) {
    case COMMAND_TYPE::ENCRYPT: {
      std::stringstream ss_in(options.GetInputFile().c_str());
      std::stringstream ss_out;
      cryptoCtx.EncryptFile(ss_in, ss_out, options.GetPassword());

      std::print("File encoded successfully\n");
    } break;

    case COMMAND_TYPE::DECRYPT: {
      std::stringstream ss_in(options.GetInputFile().c_str());
      std::stringstream ss_out;
      cryptoCtx.DecryptFile(ss_in, ss_out, options.GetPassword());

      std::print("File decoded successfully\n");
    } break;

    case COMMAND_TYPE::CHECKSUM: {
      std::stringstream ss_in(options.GetInputFile().c_str());
      std::stringstream ss_out;
      std::string hash = cryptoCtx.CalculateChecksum(ss_in);

      std::print("Checksum calculated successfully: {}\n", hash);
    } break;

    default:
      throw std::runtime_error{"Unsupported command"};
    }

  } catch (const std::exception &e) {
    std::print(std::cerr, "Error: {}\n", e.what());
    return 1;
  }

  return 0;
}