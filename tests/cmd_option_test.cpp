#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

TEST(cmd_options, optionCheck) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options"};
    ASSERT_THROW(options.Parse(1, (char **)argv), std::runtime_error);
}

TEST(cmd_options, optionCheck_2) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--command", "decrypt", "--input", "in.txt", "--output", "out.txt"};
    EXPECT_TRUE(options.Parse(7, (char **)argv));
}

TEST(cmd_options, optionCheck_3) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--help"};
    EXPECT_EXIT(options.Parse(2, (char **)argv), ::testing::ExitedWithCode(0), "");
}

TEST(cmd_options, optionCheck_4) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "encrypt"};
    ASSERT_THROW(options.Parse(2, (char **)argv), std::runtime_error);
}
TEST(cmd_options, optionCheck_5) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--password", "123", "--command", "checksum", "--input", "in.txt"};
    EXPECT_TRUE(options.Parse(7, (char **)argv));
}
TEST(cmd_options, optionCheck_6) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--password", "--command", "checksum"};
    EXPECT_FALSE(options.Parse(4, (char **)argv));
}