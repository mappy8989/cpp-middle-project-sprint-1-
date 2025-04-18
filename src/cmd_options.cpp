#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <iostream>
#include <regex>
#include <string>

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

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm_;
    auto parsed = po::command_line_parser(argc, argv).options(desc_).run();
    po::store(parsed, vm_);

    if (vm_.size() == 0) {
        throw std::runtime_error{"No commands found!"};
    }

    if (po::collect_unrecognized(parsed.options, po::include_positional).empty() == false) {
        throw std::runtime_error{"Unrecognised command found"};
    }

    const std::regex symbols_pattern("[a-zA-Z0-9!@#$%^&*()_\\-+=\\[\\]{}|\\\\;:"
                                     "\"'<>,.?/~`\\s]+$");  // only
                                                            // symbols
                                                            // from
                                                            // keyboard
    std::smatch base_match;

    if (vm_.count("help")) {
        std::cout << desc_ << "\n";
        exit(0);
    }

    if (vm_.count("command")) {
        auto it = commandMapping_.find(vm_["command"].as<std::string>());
        if (it == commandMapping_.end()) {
            throw std::runtime_error{"Incorrect command parameter"};
        }
        command_ = it->second;
    } else {
        // command must be set (except "help")
        throw std::runtime_error{"No command found"};
    }

    if (vm_.count("input")) {
        inputFile_ = vm_["input"].as<std::string>();
        if (!std::regex_match(inputFile_, base_match, symbols_pattern)) {
            throw std::runtime_error{"Incorrect input parameter"};
        }
    } else {
        // every command needs input file
        throw std::runtime_error{"No input file"};
    }

    if (vm_.count("output")) {
        outputFile_ = vm_["output"].as<std::string>();
        if (!std::regex_match(outputFile_, base_match, symbols_pattern)) {
            throw std::runtime_error{"Incorrect output parameter"};
        }
    } else if (command_ != COMMAND_TYPE::CHECKSUM) {
        // every command except "checksum" needs output file
        throw std::runtime_error{"No output file"};
    }

    if (vm_.count("password")) {
        password_ = vm_["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
