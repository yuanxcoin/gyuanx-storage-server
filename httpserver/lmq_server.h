#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace gyuanxmq {
class GyuanxMQ;
struct Allow;
class Message;
} // namespace gyuanxmq

using gyuanxmq::GyuanxMQ;

namespace gyuanx {

struct gyuanxd_key_pair_t;
class ServiceNode;
class RequestHandler;

class GyuanxmqServer {

    std::unique_ptr<GyuanxMQ> gyuanxmq_;

    // Has information about current SNs
    ServiceNode* service_node_;

    RequestHandler* request_handler_;

    // Get nodes' address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(gyuanxmq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(gyuanxmq::Message& message);

    // v2 indicates whether to use the new (v2) protocol
    void handle_onion_request(gyuanxmq::Message& message, bool v2);

    void handle_get_logs(gyuanxmq::Message& message);

    void handle_get_stats(gyuanxmq::Message& message);

    uint16_t port_ = 0;

    // Access keys for the 'service' category as binary
    std::vector<std::string> stats_access_keys;

  public:
    GyuanxmqServer(uint16_t port);
    ~GyuanxmqServer();

    // Initialize gyuanxmq
    void init(ServiceNode* sn, RequestHandler* rh,
              const gyuanxd_key_pair_t& keypair,
              const std::vector<std::string>& stats_access_key);

    uint16_t port() { return port_; }

    /// True if GyuanxMQ instance has been set
    explicit operator bool() const { return (bool)gyuanxmq_; }
    /// Dereferencing via * or -> accesses the contained GyuanxMQ instance.
    GyuanxMQ& operator*() const { return *gyuanxmq_; }
    GyuanxMQ* operator->() const { return gyuanxmq_.get(); }
};

} // namespace gyuanx
