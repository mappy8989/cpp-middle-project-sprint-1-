#pragma once

#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
  CryptoGuardCtx();
  ~CryptoGuardCtx();

  CryptoGuardCtx(const CryptoGuardCtx &) = delete;
  CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

  CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
  CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

  // API
  void EncryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password);
  void DecryptFile(std::iostream &inStream, std::iostream &outStream,
                   std::string_view password);

private:
  class Impl;
  std::unique_ptr<Impl> pImpl_;
};

// struct CryptoGuardCtx::Impl;

} // namespace CryptoGuard
