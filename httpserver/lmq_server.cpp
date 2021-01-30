#include "lmq_server.h"

#include "dev_sink.h"
#include "gyuanx_common.h"
#include "gyuanx_logger.h"
#include "gyuanxd_key.h"
#include "request_handler.h"
#include "service_node.h"
#include "utils.hpp"

#include <gyuanxmq/hex.h>
#include <gyuanxmq/gyuanxmq.h>

#include <optional>

namespace gyuanx {

std::string GyuanxmqServer::peer_lookup(std::string_view pubkey_bin) const {

    GYUANX_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    std::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        GYUANX_LOG(debug, "[LMQ] peer node not found {}!", pubkey_bin);
        return "";
    }
}

void GyuanxmqServer::handle_sn_data(gyuanxmq::Message& message) {

    GYUANX_LOG(debug, "[LMQ] handle_sn_data");
    GYUANX_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    GYUANX_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    service_node_->process_push_batch(ss.str());

    GYUANX_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending SN
    message.send_reply();
};

void GyuanxmqServer::handle_sn_proxy_exit(gyuanxmq::Message& message) {

    GYUANX_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    GYUANX_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    GYUANX_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        GYUANX_LOG(debug, "Expected 2 message parts, got {}",
                 message.data.size());
        return;
    }

    const auto& client_key = message.data[0];
    const auto& payload = message.data[1];

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    // TODO: accept string_view?
    request_handler_->process_proxy_exit(
        std::string(client_key), std::string(payload),
        [this, origin_pk, reply_tag](gyuanx::Response res) {
            GYUANX_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                this->gyuanxmq_->send(origin_pk, "REPLY", reply_tag,
                                    res.message());

            } else {
                // We reply with 2 messages which will be treated as
                // an error (rather than timeout)
                this->gyuanxmq_->send(origin_pk, "REPLY", reply_tag,
                                    fmt::format("{}", res.status()),
                                    res.message());
                GYUANX_LOG(debug, "Error: status is not OK for proxy_exit: {}",
                         res.status());
            }
        });
}

void GyuanxmqServer::handle_onion_request(gyuanxmq::Message& message, bool v2) {

    GYUANX_LOG(debug, "Got an onion request over GYUANXMQ");

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk,
                        reply_tag](gyuanx::Response res) mutable {
        GYUANX_LOG(trace, "on response: {}", to_string(res));

        std::string status = std::to_string(static_cast<int>(res.status()));

        gyuanxmq_->send(origin_pk, "REPLY", reply_tag, std::move(status),
                      res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to
        // avoid putting the error message in the log on 2.0.3+ nodes. (the
        // reply code here doesn't actually matter; the ping test only requires
        // that we provide *some* response).
        GYUANX_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(ReachType::ZMQ);
        on_response(gyuanx::Response{Status::OK, "pong"});
        return;
    }

    if (message.data.size() != 2) {
        GYUANX_LOG(error, "Expected 2 message parts, got {}",
                 message.data.size());
        on_response(gyuanx::Response{Status::BAD_REQUEST,
                                   "Incorrect number of messages"});
        return;
    }

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext),
                                        std::string(eph_key), on_response, v2);
}

void GyuanxmqServer::handle_get_logs(gyuanxmq::Message& message) {

    GYUANX_LOG(debug, "Received get_logs request via LMQ");

    auto dev_sink = dynamic_cast<gyuanx::dev_sink_mt*>(
        spdlog::get("gyuanx_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        GYUANX_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        auto err_msg = "Developer error: sink #3 is not a dev sink.";
        message.send_reply(err_msg);
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    message.send_reply(val.dump(4));
}

void GyuanxmqServer::handle_get_stats(gyuanxmq::Message& message) {

    GYUANX_LOG(debug, "Received get_stats request via LMQ");

    auto payload = service_node_->get_stats();

    message.send_reply(payload);
}

void GyuanxmqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const gyuanxd_key_pair_t& keypair,
                        const std::vector<std::string>& stats_access_keys) {

    using gyuanxmq::Allow;

    service_node_ = sn;
    request_handler_ = rh;

    for (const auto& key : stats_access_keys) {
        this->stats_access_keys.push_back(gyuanxmq::from_hex(key));
    }

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](gyuanxmq::LogLevel level, const char* file, int line,
                     std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case gyuanxmq::LogLevel::LMQ_LVL:                                            \
        GYUANX_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;
        switch (level) {
            LMQ_LOG_MAP(fatal, critical);
            LMQ_LOG_MAP(error, error);
            LMQ_LOG_MAP(warn, warn);
            LMQ_LOG_MAP(info, info);
            LMQ_LOG_MAP(trace, trace);
        default:
            GYUANX_LOG(debug, "[{}:{}]: {}", file, line, message);
        };
#undef LMQ_LOG_MAP
    };

    auto lookup_fn = [this](auto pk) { return this->peer_lookup(pk); };

    gyuanxmq_.reset(new GyuanxMQ{pubkey, seckey, true /* is service node */,
                             lookup_fn, logger});

    GYUANX_LOG(info, "GyuanxMQ is listenting on port {}", port_);

    gyuanxmq_->log_level(gyuanxmq::LogLevel::info);
    // clang-format off
    gyuanxmq_->add_category("sn", gyuanxmq::Access{gyuanxmq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
        .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); })
        ;

    gyuanxmq_->add_category("service", gyuanxmq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

    // clang-format on
    gyuanxmq_->set_general_threads(1);

    gyuanxmq_->listen_curve(
        fmt::format("tcp://0.0.0.0:{}", port_),
        [this](std::string_view /*ip*/, std::string_view pk, bool /*sn*/) {
            const auto& keys = this->stats_access_keys;
            const auto it = std::find(keys.begin(), keys.end(), pk);
            return it == keys.end() ? gyuanxmq::AuthLevel::none
                                    : gyuanxmq::AuthLevel::admin;
        });

    gyuanxmq_->MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    gyuanxmq_->start();
}

GyuanxmqServer::GyuanxmqServer(uint16_t port) : port_(port){};
GyuanxmqServer::~GyuanxmqServer() = default;

} // namespace gyuanx
