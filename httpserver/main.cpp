#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "gyuanx_logger.h"
#include "gyuanxd_key.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "lmq_server.h"
#include "request_handler.h"

#include <boost/filesystem.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <vector>

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

namespace fs = boost::filesystem;

static std::optional<fs::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifdef WIN32
    return std::nullopt;
#endif

    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        return std::nullopt;

    return fs::path(pszHome);
}

#ifdef ENABLE_SYSTEMD
static void systemd_watchdog_tick(boost::asio::steady_timer& timer,
                                  const gyuanx::ServiceNode& sn) {
    using namespace std::literals;
    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + sn.get_status_line()).c_str());
    timer.expires_after(10s);
    timer.async_wait([&](const boost::system::error_code&) {
        systemd_watchdog_tick(timer, sn);
    });
}
#endif

constexpr int EXIT_INVALID_PORT = 2;

int main(int argc, char* argv[]) {

    gyuanx::command_line_parser parser;

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        parser.print_usage();
        return EXIT_FAILURE;
    }

    auto options = parser.get_options();

    if (options.print_help) {
        parser.print_usage();
        return EXIT_SUCCESS;
    }

    if (options.print_version) {
        std::cout << version_info();
        return EXIT_SUCCESS;
    }

    if (options.data_dir.empty()) {
        if (auto home_dir = get_home_dir()) {
            if (options.testnet) {
                options.data_dir =
                    (*home_dir / ".gyuanx" / "testnet" / "storage").string();
            } else {
                options.data_dir = (*home_dir / ".gyuanx" / "storage").string();
            }
        }
    }

    if (!fs::exists(options.data_dir)) {
        fs::create_directories(options.data_dir);
    }

    gyuanx::LogLevel log_level;
    if (!gyuanx::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        gyuanx::print_log_levels();
        return EXIT_FAILURE;
    }

    gyuanx::init_logging(options.data_dir, log_level);

    if (options.testnet) {
        gyuanx::set_testnet();
        GYUANX_LOG(warn,
                 "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    print_version();

    if (options.ip == "127.0.0.1") {
        GYUANX_LOG(critical,
                 "Tried to bind gyuanx-storage to localhost, please bind "
                 "to outward facing address");
        return EXIT_FAILURE;
    }

    if (options.port == options.gyuanxd_rpc_port) {
        GYUANX_LOG(error, "Storage server port must be different from that of "
                        "Gyuanxd! Terminating.");
        exit(EXIT_INVALID_PORT);
    }

    GYUANX_LOG(info, "Setting log level to {}", options.log_level);
    GYUANX_LOG(info, "Setting database location to {}", options.data_dir);
    GYUANX_LOG(info, "Setting Gyuanxd RPC to {}:{}", options.gyuanxd_rpc_ip,
             options.gyuanxd_rpc_port);
    GYUANX_LOG(info, "Https server is listening at {}:{}", options.ip,
             options.port);
    GYUANX_LOG(info, "GyuanxMQ is listening at {}:{}", options.ip,
             options.lmq_port);

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        GYUANX_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        GYUANX_LOG(error, "AES-256-GCM is not available on this CPU");
        return EXIT_FAILURE;
    }

    {
        const auto fd_limit = util::get_fd_limit();
        if (fd_limit != -1) {
            GYUANX_LOG(debug, "Open file descriptor limit: {}", fd_limit);
        } else {
            GYUANX_LOG(debug, "Open descriptor limit: N/A");
        }
    }

    try {

        auto gyuanxd_client = gyuanx::GyuanxdClient(ioc, options.gyuanxd_rpc_ip,
                                              options.gyuanxd_rpc_port);

        // Normally we request the key from daemon, but in integrations/swarm
        // testing we are not able to do that, so we extract the key as a
        // command line option:
        gyuanx::private_key_t private_key;
        gyuanx::private_key_ed25519_t private_key_ed25519; // Unused at the moment
        gyuanx::private_key_t private_key_x25519;
#ifndef INTEGRATION_TEST
        std::tie(private_key, private_key_ed25519, private_key_x25519) =
            gyuanxd_client.wait_for_privkey();
#else
        private_key = gyuanx::gyuanxdKeyFromHex(options.gyuanxd_key);
        GYUANX_LOG(info, "GYUANXD LEGACY KEY: {}", options.gyuanxd_key);

        private_key_x25519 = gyuanx::gyuanxdKeyFromHex(options.gyuanxd_x25519_key);
        GYUANX_LOG(info, "x25519 SECRET KEY: {}", options.gyuanxd_x25519_key);

        private_key_ed25519 =
            gyuanx::private_key_ed25519_t::from_hex(options.gyuanxd_ed25519_key);

        GYUANX_LOG(info, "ed25519 SECRET KEY: {}", options.gyuanxd_ed25519_key);
#endif

        const auto public_key = gyuanx::derive_pubkey_legacy(private_key);
        GYUANX_LOG(info, "Retrieved keys from Gyuanxd; our SN pubkey is: {}",
                 util::as_hex(public_key));

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key_x25519.begin(),
                                        private_key_x25519.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        gyuanx::gyuanxd_key_pair_t gyuanxd_key_pair{private_key, public_key};

        const auto public_key_x25519 =
            gyuanx::derive_pubkey_x25519(private_key_x25519);

        GYUANX_LOG(info, "SN x25519 pubkey is: {}",
                 util::as_hex(public_key_x25519));

        const auto public_key_ed25519 =
            gyuanx::derive_pubkey_ed25519(private_key_ed25519);

        const std::string pubkey_ed25519_hex = util::as_hex(public_key_ed25519);

        GYUANX_LOG(info, "SN ed25519 pubkey is: {}", pubkey_ed25519_hex);

        gyuanx::gyuanxd_key_pair_t gyuanxd_key_pair_x25519{private_key_x25519,
                                                     public_key_x25519};

        for (const auto& key : options.stats_access_keys) {
            GYUANX_LOG(info, "Stats access key: {}", key);
        }

        // We pass port early because we want to send it in the first ping to
        // Gyuanxd (in ServiceNode's constructor), but don't want to initialize
        // the rest of lmq server before we have a reference to ServiceNode
        gyuanx::GyuanxmqServer gyuanxmq_server(options.lmq_port);

        // TODO: SN doesn't need gyuanxmq_server, just the lmq components
        gyuanx::ServiceNode service_node(ioc, worker_ioc, options.port,
                                       gyuanxmq_server, gyuanxd_key_pair,
                                       pubkey_ed25519_hex, options.data_dir,
                                       gyuanxd_client, options.force_start);

        gyuanx::RequestHandler request_handler(ioc, service_node, gyuanxd_client,
                                             channel_encryption);

        gyuanxmq_server.init(&service_node, &request_handler,
                           gyuanxd_key_pair_x25519, options.stats_access_keys);

        RateLimiter rate_limiter;

        gyuanx::Security security(gyuanxd_key_pair, options.data_dir);

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        boost::asio::steady_timer systemd_watchdog_timer(ioc);
        systemd_watchdog_tick(systemd_watchdog_timer, service_node);
#endif

        gyuanx::http_server::run(ioc, options.ip, options.port, options.data_dir,
                               service_node, request_handler, rate_limiter,
                               security);
    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        std::cerr << "Exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown exception caught in main." << std::endl;
        return EXIT_FAILURE;
    }
}
