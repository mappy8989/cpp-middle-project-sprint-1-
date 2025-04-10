#include "cmd_options.h"
#include <boost/program_options/value_semantic.hpp>
#include <iostream>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(),
                                                        "commands 'encrypt', 'decrypt' or 'checksum'")(
        "input", po::value<std::string>(), "path to the input file")("output", po::value<std::string>(),
                                                                     "path to the output file to be saved")(
        "password", po::value<std::string>(), "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm_;
    po::store(po::parse_command_line(argc, argv, desc_), vm_);

    if (vm_.count("help")) {
        std::cout << desc_ << "\n";
        exit(0);
    }

    return true;
}

}  // namespace CryptoGuard
