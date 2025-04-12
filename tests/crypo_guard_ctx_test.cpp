#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iostream>
#include <stdexcept>

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

  ASSERT_THROW(guard.EncryptFile(input, out, "1234"), std::logic_error);
}

TEST(crypto_guard, decrypt_1) {
  const std::string test_str =
      "012345678901234567890123456789012345678901234567890123456789";

  CryptoGuard::CryptoGuardCtx guard;
  std::stringstream input(test_str);
  std::stringstream out;

  guard.EncryptFile(input, out, "1234");

  std::stringstream plain_text;
  guard.DecryptFile(out, plain_text, "1234");

  // as we have padding in the output buffer, we need only a string with
  // terminating NULL at the end
  std::string plain_string = plain_text.rdbuf()->str().substr(
      0, strlen(plain_text.rdbuf()->str().data()));

  EXPECT_EQ(test_str, plain_string);
}

TEST(crypto_guard, decrypt_2) {
  const std::string test_str =
      "012345678901234567890123456789012345678901234567890123456789";

  CryptoGuard::CryptoGuardCtx guard;
  std::stringstream input(test_str);
  std::stringstream out;

  guard.EncryptFile(input, out, "1234");

  std::stringstream plain_text;
  ASSERT_THROW(guard.DecryptFile(out, plain_text, "5678"), std::logic_error);
}

TEST(crypto_guard, decrypt_3) {
  const std::string test_str = "Hello, world!";

  CryptoGuard::CryptoGuardCtx guard;
  std::stringstream input(test_str);
  std::stringstream out;

  guard.EncryptFile(input, out, "1234");

  std::stringstream plain_text;
  guard.DecryptFile(out, plain_text, "1234");

  // as we have padding in the output buffer, we need only a string with
  // terminating NULL at the end
  std::string plain_string = plain_text.rdbuf()->str().substr(
      0, strlen(plain_text.rdbuf()->str().data()));

  EXPECT_NE(test_str.substr(0, test_str.size() / 2), plain_string);
}