#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <optional>

#include "../external/json.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include "loki_common.h"
#include "gyuanxd_key.h"
#include "swarm.h"

constexpr auto LOKI_SENDER_SNODE_PUBKEY_HEADER = "X-Loki-Snode-PubKey";
constexpr auto LOKI_SNODE_SIGNATURE_HEADER = "X-Loki-Snode-Signature";
constexpr auto LOKI_SENDER_KEY_HEADER = "X-Sender-Public-Key";
constexpr auto LOKI_TARGET_SNODE_KEY = "X-Target-Snode-Key";
constexpr auto LOKI_LONG_POLL_HEADER = "X-Loki-Long-Poll";

template <typename T>
class ChannelEncryption;

class RateLimiter;

namespace http = boost::beast::http; // from <boost/beast/http.hpp>
namespace ssl = boost::asio::ssl;    // from <boost/asio/ssl.hpp>

using request_t = http::request<http::string_body>;
using response_t = http::response<http::string_body>;

namespace loki {

std::shared_ptr<request_t> build_post_request(const char* target,
                                              std::string&& data);

struct Security;

class RequestHandler;
class Response;

namespace storage {
struct Item;
}

using storage::Item;

enum class SNodeError { NO_ERROR, ERROR_OTHER, NO_REACH, HTTP_ERROR };

struct sn_response_t {
    SNodeError error_code;
    std::shared_ptr<std::string> body;
    std::optional<response_t> raw_response;
};

template <typename OStream>
OStream& operator<<(OStream& os, const sn_response_t& res) {
    switch (res.error_code) {
    case SNodeError::NO_ERROR:
        os << "NO_ERROR";
        break;
    case SNodeError::ERROR_OTHER:
        os << "ERROR_OTHER";
        break;
    case SNodeError::NO_REACH:
        os << "NO_REACH";
        break;
    case SNodeError::HTTP_ERROR:
        os << "HTTP_ERROR";
        break;
    }

    return os << "(" << (res.body ? *res.body : "n/a") << ")";
}

struct blockchain_test_answer_t {
    uint64_t res_height;
};

/// Blockchain test parameters
struct bc_test_params_t {
    uint64_t max_height;
    uint64_t seed;
};

using http_callback_t = std::function<void(sn_response_t)>;

class LokidClient {

    boost::asio::io_context& ioc_;
    std::string gyuanxd_rpc_ip_;
    const uint16_t gyuanxd_rpc_port_;

  public:
    LokidClient(boost::asio::io_context& ioc, std::string ip, uint16_t port);
    void make_gyuanxd_request(std::string_view method,
                            const nlohmann::json& params,
                            http_callback_t&& cb) const;
    void make_custom_gyuanxd_request(const std::string& daemon_ip,
                                   const uint16_t daemon_port,
                                   std::string_view method,
                                   const nlohmann::json& params,
                                   http_callback_t&& cb) const;
    // Synchronously fetches the private key from gyuanxd.  Designed to be called
    // *before* the io_context has been started (this runs it, waits for a
    // successful fetch, then restarts it when finished).
    std::tuple<private_key_t, private_key_ed25519_t, private_key_t>
    wait_for_privkey();
};

constexpr auto SESSION_TIME_LIMIT = std::chrono::seconds(30);

void make_http_request(boost::asio::io_context& ioc, const std::string& ip,
                       uint16_t port, const std::shared_ptr<request_t>& req,
                       http_callback_t&& cb);

class HttpClientSession
    : public std::enable_shared_from_this<HttpClientSession> {

    using tcp = boost::asio::ip::tcp;

    boost::asio::io_context& ioc_;
    tcp::socket socket_;
    tcp::endpoint endpoint_;
    http_callback_t callback_;
    boost::asio::steady_timer deadline_timer_;

    boost::beast::flat_buffer buffer_;
    /// NOTE: this needs to be a shared pointer since
    /// it is very common for the same request to be
    /// sent to multiple snodes
    std::shared_ptr<request_t> req_;
    response_t res_;

    bool used_callback_ = false;
    bool needs_cleanup = true;

    void on_connect();

    void on_write(boost::system::error_code ec, std::size_t bytes_transferred);

    void on_read(boost::system::error_code ec, std::size_t bytes_transferred);

    void trigger_callback(SNodeError error,
                          std::shared_ptr<std::string>&& body);

    void clean_up();

  public:
    // Resolver and socket require an io_context
    HttpClientSession(boost::asio::io_context& ioc, const tcp::endpoint& ep,
                      const std::shared_ptr<request_t>& req,
                      http_callback_t&& cb);

    // initiate the client connection
    void start();

    ~HttpClientSession();
};

namespace http_server {

class connection_t : public std::enable_shared_from_this<connection_t> {

    using tcp = boost::asio::ip::tcp;

  private:
    boost::asio::io_context& ioc_;
    ssl::context& ssl_ctx_;

    // The socket for the currently connected client.
    tcp::socket socket_;

    // The buffer for performing reads.
    boost::beast::flat_buffer buffer_{8192};
    ssl::stream<tcp::socket&> stream_;
    const Security& security_;

    // Contains the request message
    http::request_parser<http::string_body> request_;

    // The response message.
    response_t response_;

    // whether the response should be sent asyncronously,
    // as opposed to directly after connection_t::process_request
    bool delay_response_ = false;

    // TODO: remove SN, only use Reqeust Handler as a mediator
    ServiceNode& gnode_;

    RequestHandler& request_handler_;

    RateLimiter& rate_limiter_;

    // The timer for repeating an action within one connection
    boost::asio::steady_timer repeat_timer_;
    int repetition_count_ = 0;
    std::chrono::time_point<std::chrono::steady_clock> start_timestamp_;

    // The timer for putting a deadline on connection processing.
    boost::asio::steady_timer deadline_;

    /// TODO: move these if possible
    std::map<std::string, std::string> header_;

    std::stringstream body_stream_;

    // Note that we are only sending a single message through the
    // notification mechanism. If we somehow accumulated multiple
    // messages before notification event happens (unlikely), the
    // following messages will be delivered with the client's
    // consequent (and immediate) retrieve request
    struct notification_context_t {
        // The timer used for internal db polling
        boost::asio::steady_timer timer;
        // the message is stored here momentarily; needed because
        // we can't pass it using current notification mechanism
        std::optional<message_t> message;
        // Messenger public key that this connection is registered for
        std::string pubkey;
    };

    std::optional<notification_context_t> notification_ctx_;

    // If present, this function will be called just before
    // writing the response
    std::function<void(response_t&)> response_modifier_;

  public:
    connection_t(boost::asio::io_context& ioc, ssl::context& ssl_ctx,
                 tcp::socket socket, ServiceNode& sn, RequestHandler& rh,
                 RateLimiter& rate_limiter, const Security& security);

    ~connection_t();

    // Connection index, mainly used for debugging
    uint64_t conn_idx;

    /// Initiate the asynchronous operations associated with the connection.
    void start();

    void notify(const message_t* msg);

  private:
    void do_handshake();
    void on_handshake(boost::system::error_code ec);
    /// Asynchronously receive a complete request message.
    void read_request();

    void do_close();
    void on_shutdown(boost::system::error_code ec);

    /// process GET /get_stats/v1
    void on_get_stats();

    /// Determine what needs to be done with the request message
    /// (synchronously).
    void process_request();

    /// Unsubscribe listener (if any) and shutdown the connection
    void clean_up();

    /// Asynchronously transmit the response message.
    void write_response();

    /// Syncronously (?) process client store/load requests
    void process_client_req_rate_limited();

    void process_swarm_req(std::string_view target);

    /// Process onion request from the client (json)
    void process_onion_req_v1();

    /// Process onion request from the client (binary)
    void process_onion_req_v2();

    void process_proxy_req();

    void process_file_proxy_req();

    // Check whether we have spent enough time on this connection.
    void register_deadline();

    /// Process storage test request and repeat if necessary
    void process_storage_test_req(uint64_t height,
                                  const std::string& tester_addr,
                                  const std::string& msg_hash);

    void process_blockchain_test_req(uint64_t height,
                                     const std::string& tester_pk,
                                     bc_test_params_t params);

    void set_response(const Response& res);

    bool parse_header(const char* key);

    template <typename... Args>
    bool parse_header(const char* first, Args... args);

    bool validate_snode_request();
};

void run(boost::asio::io_context& ioc, const std::string& ip, uint16_t port,
         const boost::filesystem::path& base_path, ServiceNode& sn,
         RequestHandler& rh, RateLimiter& rate_limiter, Security&);

} // namespace http_server

constexpr const char* error_string(SNodeError err) {
    switch (err) {
    case loki::SNodeError::NO_ERROR:
        return "NO_ERROR";
    case loki::SNodeError::ERROR_OTHER:
        return "ERROR_OTHER";
    case loki::SNodeError::NO_REACH:
        return "NO_REACH";
    case loki::SNodeError::HTTP_ERROR:
        return "HTTP_ERROR";
    default:
        return "[UNKNOWN]";
    }
}

struct CiphertextPlusJson {
    std::string ciphertext;
    std::string json;
};

// TODO: move this from http_connection.h after refactoring
auto parse_combined_payload(const std::string& payload) -> CiphertextPlusJson;

} // namespace loki

namespace fmt {

template <>
struct formatter<loki::SNodeError> {

    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const loki::SNodeError& err, FormatContext& ctx) {
        return format_to(ctx.out(), error_string(err));
    }
};

} // namespace fmt
