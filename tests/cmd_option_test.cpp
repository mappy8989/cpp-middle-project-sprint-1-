#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

TEST(cmd_options, no_option_added) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options"};
    ASSERT_THROW(options.Parse(1, (char **)argv), std::runtime_error);
}

TEST(cmd_options, options_added_ok) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--command", "decrypt", "--input", "in.txt", "--output", "out.txt"};
    ASSERT_NO_THROW(options.Parse(7, (char **)argv));
}

TEST(cmd_options, options_help) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--help"};
    EXPECT_EXIT(options.Parse(2, (char **)argv), ::testing::ExitedWithCode(0), "");
}

TEST(cmd_options, too_few_options) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "encrypt"};
    ASSERT_THROW(options.Parse(2, (char **)argv), std::runtime_error);
}

TEST(cmd_options, options_added_ok_2) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--command", "checksum", "--input", "in.txt"};
    ASSERT_NO_THROW(options.Parse(5, (char **)argv));
}

TEST(cmd_options, no_password) {
    CryptoGuard::ProgramOptions options;
    const char *argv[] = {"cmd_options", "--password", "--command", "checksum"};
    ASSERT_THROW(options.Parse(4, (char **)argv), std::runtime_error);
}