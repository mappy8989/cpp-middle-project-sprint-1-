#include "crypto_guard_ctx.h"
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <iostream>
#include <stdexcept>
#include <string>

TEST(crypto_guard, encrypt_string) {
    std::stringstream input("Simple string!");
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx guard;

    ASSERT_NO_THROW(guard.EncryptFile(input, out, "1234"));
}

TEST(crypto_guard, encrypt_check_size) {
    std::stringstream input("Simple string!");
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx guard;

    guard.EncryptFile(input, out, "1234");
    std::string line;
    std::getline(out, line);
    EXPECT_TRUE(line.size() > 0);
}

TEST(crypto_guard, encrypt_fail_stream) {
    std::stringstream input("test");
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx guard;

    input.setstate(std::ios::failbit);

    ASSERT_THROW(guard.EncryptFile(input, out, "1234"), std::runtime_error);
}

TEST(crypto_guard, decrypt_short_buf) {
    const int BYTE_BUF_SIZE = 7;
    const std::array<char, BYTE_BUF_SIZE> byte_buf_in = {1, 2, 3, 4, 5, -100, -45};

    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream input(byte_buf_in.data());
    std::stringstream out;

    guard.EncryptFile(input, out, "1234");

    std::stringstream plain_text;
    guard.DecryptFile(out, plain_text, "1234");

    std::string plain_string = plain_text.str();
    EXPECT_EQ(0, memcmp(byte_buf_in.data(), plain_string.data(), BYTE_BUF_SIZE));
}

TEST(crypto_guard, decrypt_diff_passwords) {
    const int BYTE_BUF_SIZE = 7;
    const std::array<char, BYTE_BUF_SIZE> byte_buf_in = {1, 2, 3, 4, 5, -100, -45};

    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream input(byte_buf_in.data());
    std::stringstream out;

    guard.EncryptFile(input, out, "1234");

    std::stringstream plain_text;
    guard.DecryptFile(out, plain_text, "5678");

    std::string plain_string = plain_text.str();
    EXPECT_NE(0, memcmp(byte_buf_in.data(), plain_string.data(), BYTE_BUF_SIZE));
}

TEST(crypto_guard, decrypt_long_buf) {
    const int BYTE_BUF_SIZE = 1000;
    char byte_buf_in[BYTE_BUF_SIZE] = {};

    uint8_t temp = 0;
    for (int i = 0; i < BYTE_BUF_SIZE; i++) {
        byte_buf_in[i] = temp++;
    }

    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream input(byte_buf_in);
    std::stringstream out;

    guard.EncryptFile(input, out, "1234");

    std::stringstream plain_text;
    guard.DecryptFile(out, plain_text, "1234");

    std::string plain_string = plain_text.str();
    EXPECT_NE(0, memcmp(byte_buf_in, plain_string.data(), BYTE_BUF_SIZE));
}

TEST(crypto_guard, hash_1) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream input("123456789");
    std::stringstream out;

    const std::string correct_hash_str = "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225";

    std::string hash = guard.CalculateChecksum(input);

    EXPECT_EQ(correct_hash_str, hash);
}

TEST(crypto_guard, hash_2) {
    CryptoGuard::CryptoGuardCtx guard;
    std::stringstream input("1 1");
    std::stringstream out;

    const std::string correct_hash_str = "020a7c91e30725bb191818987340dec6040aff93923840de685e1e1d7b3d071a";

    std::string hash = guard.CalculateChecksum(input);

    EXPECT_EQ(correct_hash_str, hash);
}