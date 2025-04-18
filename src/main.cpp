#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
  try {
    OpenSSL_add_all_algorithms();

    CryptoGuard::ProgramOptions options;
    options.Parse(argc, argv);

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
    switch (options.GetCommand()) {
    case COMMAND_TYPE::ENCRYPT:
    case COMMAND_TYPE::DECRYPT: {
      std::fstream fileStream_in(options.GetInputFile(), std::ios::in);
      if (!fileStream_in) {
        throw std::runtime_error("Cannot open input file");
      }
      std::fstream fileStream_out(options.GetOutputFile(),
                                  std::ios::out | std::ios::trunc);
      if (!fileStream_out) {
        throw std::runtime_error("Cannot open output file");
      }

      if (options.GetCommand() == COMMAND_TYPE::ENCRYPT) {
        cryptoCtx.EncryptFile(fileStream_in, fileStream_out,
                              options.GetPassword());
      } else {
        cryptoCtx.DecryptFile(fileStream_in, fileStream_out,
                              options.GetPassword());
      }

      std::print("File {} successfully\n",
                 options.GetCommand() == COMMAND_TYPE::ENCRYPT ? "encocded"
                                                               : "decoded");
    } break;

    case COMMAND_TYPE::CHECKSUM: {
      std::fstream fileStream_in(options.GetInputFile());
      if (!fileStream_in) {
        throw std::runtime_error("Cannot open input file");
      }

      std::string hash = cryptoCtx.CalculateChecksum(fileStream_in);

      std::print("Checksum calculated successfully:\n{}\n", hash);
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