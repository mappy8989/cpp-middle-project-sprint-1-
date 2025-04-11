#include "crypto_guard_ctx.h"
#include <iostream>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl {
  std::string CalculateChecksum(std::iostream &inStream) {
    return "NOT_IMPLEMENTED";
  }

  void EncryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {}
  void DecryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password) {}
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  pImpl_->DecryptFile(inStream, outStream, password);
}

} // namespace CryptoGuard
