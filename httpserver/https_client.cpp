#include "https_client.h"
#include "gyuanx_logger.h"
#include "net_stats.h"
#include "signature.h"

#include <boost/algorithm/string/erase.hpp>
#include <openssl/x509.h>

namespace gyuanx {

using error_code = boost::system::error_code;

void make_https_request(boost::asio::io_context& ioc,
                        const std::string& sn_address, uint16_t port,
                        const std::string& sn_pubkey_b32z,
                        const std::shared_ptr<request_t>& req,
                        http_callback_t&& cb) {

    error_code ec;
    boost::asio::ip::tcp::resolver resolver(ioc);
#ifdef INTEGRATION_TEST
    const auto resolve_results =
        resolver.resolve("0.0.0.0", std::to_string(port), ec);
#else

    if (sn_address == "0.0.0.0") {
        GYUANX_LOG(debug, "Could not initiate request to snode (we don't know "
                        "their IP yet).");

        cb(sn_response_t{SNodeError::NO_REACH, nullptr});
        return;
    }

    const auto resolve_results =
        resolver.resolve(sn_address, std::to_string(port), ec);
#endif

    static ssl::context ctx{ssl::context::tlsv12_client};

    auto session = std::make_shared<HttpsClientSession>(
        ioc, ctx, std::move(resolve_results), req, std::move(cb),
        sn_pubkey_b32z);

    session->start();
}

void make_https_request(boost::asio::io_context& ioc, const std::string& url,
                        const std::shared_ptr<request_t>& req,
                        http_callback_t&& cb) {

    static boost::asio::ip::tcp::resolver resolver(ioc);

    constexpr char prefix[] = "https://";
    std::string query = url;

    if (url.find(prefix) == 0) {
        query.erase(0, sizeof(prefix) - 1);
    }

    auto resolve_handler = [&ioc, req, query, cb = std::move(cb)](
                               const boost::system::error_code& ec,
                               boost::asio::ip::tcp::resolver::results_type
                                   resolve_results) mutable {
        if (ec) {
            GYUANX_LOG(error, "DNS resolution error for {}: {}", query,
                     ec.message());
            cb({SNodeError::ERROR_OTHER});
            return;
        }

        static ssl::context ctx{ssl::context::tlsv12_client};

        auto session = std::make_shared<HttpsClientSession>(
            ioc, ctx, std::move(resolve_results), req, std::move(cb),
            std::nullopt);

        session->start();
    };

    constexpr char https_port[] = "443";

    resolver.async_resolve(
        query, https_port,
        boost::asio::ip::tcp::resolver::query::numeric_service,
        resolve_handler);
}

static std::string x509_to_string(X509* x509) {
    BIO* bio_out = BIO_new(BIO_s_mem());
    if (!bio_out) {
        GYUANX_LOG(critical, "Could not allocate openssl BIO");
        return "";
    }
    if (!PEM_write_bio_X509(bio_out, x509)) {
        GYUANX_LOG(critical, "Could not write x509 cert to openssl BIO");
        return "";
    }
    BUF_MEM* bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    std::string pem = std::string(bio_buf->data, bio_buf->length);
    if (!BIO_free(bio_out)) {
        GYUANX_LOG(critical, "Could not free openssl BIO");
    }
    return pem;
}

HttpsClientSession::HttpsClientSession(
    boost::asio::io_context& ioc, ssl::context& ssl_ctx,
    tcp::resolver::results_type resolve_results,
    const std::shared_ptr<request_t>& req, http_callback_t&& cb,
    std::optional<std::string> sn_pubkey_b32z)
    : ioc_(ioc), ssl_ctx_(ssl_ctx), resolve_results_(resolve_results),
      callback_(cb), deadline_timer_(ioc), stream_(ioc, ssl_ctx_), req_(req),
      server_pub_key_b32z_(std::move(sn_pubkey_b32z)) {

    get_net_stats().https_connections_out++;

    static uint64_t connection_count = 0;
    this->connection_idx = connection_count++;
}

void HttpsClientSession::start() {
    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (!SSL_set_tlsext_host_name(stream_.native_handle(), "service node")) {
        boost::beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                    boost::asio::error::get_ssl_category()};
        GYUANX_LOG(critical, "{}", ec.message());
        return;
    }
    boost::asio::async_connect(
        stream_.next_layer(), resolve_results_,
        [this, self = shared_from_this()](boost::system::error_code ec,
                                          const tcp::endpoint& endpoint) {
            /// TODO: I think I should just call again if ec ==
            /// EINTR
            if (ec) {
                /// Don't forget to print the error from where we call this!
                /// (similar to http)
                GYUANX_LOG(debug,
                         "[https client]: could not connect to {}:{}, message: "
                         "{} ({})",
                         endpoint.address().to_string(), endpoint.port(),
                         ec.message(), ec.value());
                trigger_callback(SNodeError::NO_REACH, nullptr);
                return;
            }

            self->on_connect();
        });

    deadline_timer_.expires_after(SESSION_TIME_LIMIT);
    deadline_timer_.async_wait(
        [self = shared_from_this()](const error_code& ec) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    GYUANX_LOG(error,
                             "Deadline timer failed in https client session "
                             "[{}: {}]",
                             ec.value(), ec.message());
                }
            } else {
                GYUANX_LOG(debug, "client socket timed out");
                self->do_close();
            }
        });
}

void HttpsClientSession::on_connect() {
    GYUANX_LOG(trace, "on connect, connection idx: {}", this->connection_idx);

    const auto sockfd = stream_.lowest_layer().native_handle();
    GYUANX_LOG(trace, "Open https client socket: {}", sockfd);
    get_net_stats().record_socket_open(sockfd);

    stream_.set_verify_mode(ssl::verify_none);

    stream_.set_verify_callback(
        [this](bool preverified, ssl::verify_context& ctx) -> bool {
            if (!preverified) {
                X509_STORE_CTX* handle = ctx.native_handle();
                X509* x509 = X509_STORE_CTX_get0_cert(handle);
                server_cert_ = x509_to_string(x509);
            }
            return true;
        });
    stream_.async_handshake(ssl::stream_base::client,
                            std::bind(&HttpsClientSession::on_handshake,
                                      shared_from_this(),
                                      std::placeholders::_1));
}

void HttpsClientSession::on_handshake(boost::system::error_code ec) {
    if (ec) {
        GYUANX_LOG(error, "Failed to perform a handshake with {}: {}",
                 server_pub_key_b32z_.value_or("(not snode)"), ec.message());

        return;
    }

    http::async_write(stream_, *req_,
                      std::bind(&HttpsClientSession::on_write,
                                shared_from_this(), std::placeholders::_1,
                                std::placeholders::_2));
}

void HttpsClientSession::on_write(error_code ec, size_t bytes_transferred) {

    GYUANX_LOG(trace, "on write");
    if (ec) {
        GYUANX_LOG(error, "Https error on write, ec: {}. Message: {}", ec.value(),
                 ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr);
        return;
    }

    GYUANX_LOG(trace, "Successfully transferred {} bytes.", bytes_transferred);

    // Receive the HTTP response
    http::async_read(stream_, buffer_, res_,
                     std::bind(&HttpsClientSession::on_read, shared_from_this(),
                               std::placeholders::_1, std::placeholders::_2));
}

bool HttpsClientSession::verify_signature() {

    if (!server_pub_key_b32z_)
        return true;

    const auto it = res_.find(GYUANX_SNODE_SIGNATURE_HEADER);
    if (it == res_.end()) {
        GYUANX_LOG(warn, "no signature found in header from {}",
                 *server_pub_key_b32z_);
        return false;
    }
    // signature is expected to be base64 enoded
    const auto signature = it->value().to_string();
    const auto hash = hash_data(server_cert_);
    return check_signature(signature, hash, *server_pub_key_b32z_);
}

void HttpsClientSession::on_read(error_code ec, size_t bytes_transferred) {

    GYUANX_LOG(trace, "Successfully received {} bytes", bytes_transferred);

    if (!ec || (ec == http::error::end_of_stream)) {

        if (http::to_status_class(res_.result_int()) ==
            http::status_class::successful) {

            if (server_pub_key_b32z_ && !verify_signature()) {
                GYUANX_LOG(debug, "Bad signature from {}", *server_pub_key_b32z_);
                trigger_callback(SNodeError::ERROR_OTHER, nullptr, res_);
            } else {
                auto body = std::make_shared<std::string>(res_.body());
                trigger_callback(SNodeError::NO_ERROR, std::move(body), res_);
            }

        } else {
            trigger_callback(SNodeError::ERROR_OTHER, nullptr, res_);
        }

    } else {

        /// Do we need to handle `operation aborted` separately here (due to
        /// deadline timer)?
        GYUANX_LOG(error, "Error on read: {}. Message: {}", ec.value(),
                 ec.message());
        trigger_callback(SNodeError::ERROR_OTHER, nullptr, res_);
    }

    // Gracefully close the socket
    do_close();

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != boost::system::errc::not_connected) {

        GYUANX_LOG(error, "ec: {}. Message: {}", ec.value(), ec.message());
        return;
    }

    // If we get here then the connection is closed gracefully
}

void HttpsClientSession::trigger_callback(
    SNodeError error, std::shared_ptr<std::string>&& body,
    std::optional<response_t> raw_response) {
    ioc_.post(std::bind(callback_, sn_response_t{error, body, raw_response}));
    used_callback_ = true;
    deadline_timer_.cancel();
}

void HttpsClientSession::do_close() {

    // Note: I don't think both the server and the client
    // should initiate the shutdown, but I'm going to ignore
    // this error as we will remove https soon

    // Gracefully close the stream
    stream_.async_shutdown(std::bind(&HttpsClientSession::on_shutdown,
                                     shared_from_this(),
                                     std::placeholders::_1));
}

void HttpsClientSession::on_shutdown(boost::system::error_code ec) {
    if (ec == boost::asio::error::eof) {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec.assign(0, ec.category());
    } else if (ec) {
        // This one is too noisy, so demoted to debug:
        GYUANX_LOG(trace, "could not shutdown stream gracefully: {} ({})",
                 ec.message(), ec.value());
    }

    const auto sockfd = stream_.lowest_layer().native_handle();
    GYUANX_LOG(trace, "Close https socket: {}", sockfd);
    get_net_stats().record_socket_close(sockfd);

    stream_.lowest_layer().close();

    // If we get here then the connection is closed gracefully
}

/// We execute callback (if haven't already) here to make sure it is called
HttpsClientSession::~HttpsClientSession() {

    if (!used_callback_) {
        // If we destroy the session before posting the callback,
        // it must be due to some error
        ioc_.post(std::bind(callback_,
                            sn_response_t{SNodeError::ERROR_OTHER, nullptr}));
    }

    get_net_stats().https_connections_out--;
}
} // namespace gyuanx
