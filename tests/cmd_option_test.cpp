#include "cmd_options.h"
#include <gtest/gtest.h>
#include <memory>

TEST(cmd_options, optionCheck) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options"};
  EXPECT_TRUE(options.Parse(1, (char **)argv));
}

TEST(cmd_options, optionCheck_2) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options", "--command", "decrypt"};
  EXPECT_TRUE(options.Parse(3, (char **)argv));
}

TEST(cmd_options, optionCheck_3) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options", "--help"};
  EXPECT_EXIT(options.Parse(2, (char **)argv), ::testing::ExitedWithCode(0),
              "");
}

TEST(cmd_options, optionCheck_4) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options", "encrypt"};
  EXPECT_FALSE(options.Parse(2, (char **)argv));
}
TEST(cmd_options, optionCheck_5) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options", "--password", "123", "--command",
                        "checksum"};
  EXPECT_TRUE(options.Parse(5, (char **)argv));
}
TEST(cmd_options, optionCheck_6) {
  CryptoGuard::ProgramOptions options;
  const char *argv[] = {"cmd_options", "--password", "--command", "checksum"};
  EXPECT_FALSE(options.Parse(4, (char **)argv));
}