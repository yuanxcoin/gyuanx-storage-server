#include "command_line.h"
#include "gyuanx_logger.h"

#include <boost/filesystem.hpp>

#include <iostream>

namespace gyuanx {

namespace po = boost::program_options;
namespace fs = boost::filesystem;

const command_line_options& command_line_parser::get_options() const {
    return options_;
}

void command_line_parser::parse_args(int argc, char* argv[]) {
    std::string config_file;
    po::options_description all, hidden;
    // clang-format off
    desc_.add_options()
        ("data-dir", po::value(&options_.data_dir), "Path to persistent data (defaults to ~/.gyuanx/storage)")
        ("config-file", po::value(&config_file), "Path to custom config file (defaults to `storage-server.conf' inside --data-dir)")
        ("log-level", po::value(&options_.log_level), "Log verbosity level, see Log Levels below for accepted values")
        ("gyuanxd-rpc-ip", po::value(&options_.gyuanxd_rpc_port), "RPC IP on which the local gyuanx daemon is listening (usually localhost)")
        ("gyuanxd-rpc-port", po::value(&options_.gyuanxd_rpc_port), "RPC port on which the local gyuanx daemon is listening")
        ("lmq-port", po::value(&options_.lmq_port), "Port used by gyuanxMQ")
        ("testnet", po::bool_switch(&options_.testnet), "Start storage server in testnet mode")
        ("force-start", po::bool_switch(&options_.force_start), "Ignore the initialisation ready check")
        ("bind-ip", po::value(&options_.ip)->default_value("0.0.0.0"), "IP to which to bind the server")
        ("version,v", po::bool_switch(&options_.print_version), "Print the version of this binary")
        ("help", po::bool_switch(&options_.print_help),"Shows this help message")
        ("stats-access-key", po::value(&options_.stats_access_keys)->multitoken(), "A public key (x25519) that will be given access to the `get_stats` lmq endpoint");
        // Add hidden ip and port options.  You technically can use the `--ip=` and `--port=` with
        // these here, but they are meant to be positional.  More usefully, you can specify `ip=`
        // and `port=` in the config file to specify them.
    hidden.add_options()
        ("ip", po::value<std::string>(), "(unused)")
        ("port", po::value(&options_.port), "Port to listen on")
        ("gyuanxd-key", po::value(&options_.gyuanxd_key), "Legacy secret key (test only)")
        ("gyuanxd-x25519-key", po::value(&options_.gyuanxd_x25519_key), "x25519 secret key (test only)")
        ("gyuanxd-ed25519-key", po::value(&options_.gyuanxd_ed25519_key), "ed25519 public key (test only)");
    // clang-format on

    all.add(desc_).add(hidden);
    po::positional_options_description pos_desc;
    pos_desc.add("ip", 1);
    pos_desc.add("port", 1);

    binary_name_ = fs::basename(argv[0]);

    po::variables_map vm;

    po::store(po::command_line_parser(argc, argv)
                  .options(all)
                  .positional(pos_desc)
                  .run(),
              vm);
    po::notify(vm);

    if (config_file.empty()) {
        config_file =
            (fs::path(options_.data_dir) / "storage-server.conf").string();
    }

    if (fs::exists(config_file)) {
        po::store(po::parse_config_file<char>(config_file.c_str(), all), vm);
        po::notify(vm);
    } else if (vm.count("config-file")) {
        throw std::runtime_error(
            "path provided in --config-file does not exist");
    }

    if (options_.print_version || options_.print_help) {
        return;
    }

    if (options_.testnet && !vm.count("gyuanxd-rpc-port")) {
        options_.gyuanxd_rpc_port = 48157;
    }

    if (!vm.count("lmq-port")) {
        throw std::runtime_error(
            "lmq-port command line option is not specified");
    }

    if (!vm.count("ip") || !vm.count("port")) {
        throw std::runtime_error(
            "Invalid option: address and/or port missing.");
    }
}

void command_line_parser::print_usage() const {
    std::cerr << "Usage: " << binary_name_ << " <address> <port> [...]\n\n";

    desc_.print(std::cerr);

    std::cerr << std::endl;

    print_log_levels();
}
} // namespace gyuanx
