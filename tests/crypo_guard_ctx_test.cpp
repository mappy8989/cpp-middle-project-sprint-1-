#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iostream>

TEST(crypto_guard, encrypt_1) {
  std::stringstream input("Simple string!");
  std::stringstream out;
  CryptoGuard::CryptoGuardCtx guard;

  ASSERT_NO_THROW(guard.EncryptFile(input, out, "1234"));
}

TEST(crypto_guard, encrypt_2) {
  std::stringstream input("Simple string!");
  std::stringstream out;
  CryptoGuard::CryptoGuardCtx guard;

  guard.EncryptFile(input, out, "1234");
  std::string line;
  std::getline(out, line);
  EXPECT_TRUE(line.size() > 0);
}

TEST(crypto_guard, encrypt_3) {
  std::stringstream input("test");
  std::stringstream out;
  CryptoGuard::CryptoGuardCtx guard;

  input.setstate(std::ios::failbit);

  ASSERT_THROW(guard.EncryptFile(input, out, "1234"), std::runtime_error);
}