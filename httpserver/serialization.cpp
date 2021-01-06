#include "serialization.h"

/// TODO: should only be aware of messages
#include "Item.hpp"
#include "loki_logger.h"
#include "gnode.h"

#include <boost/endian/conversion.hpp>
#include <boost/format.hpp>

using loki::storage::Item;

namespace loki {

template <typename T>
static T deserialize_integer(std::string::const_iterator& it) {

    const auto b1 = reinterpret_cast<const T&>(*it);
    it += sizeof(T);
    return boost::endian::little_to_native(b1);
}

template <typename T>
static void serialize_integer(std::string& buf, T a) {
    boost::endian::native_to_little_inplace(a);
    const auto p = reinterpret_cast<const char*>(&a);
    buf.insert(buf.size(), p, sizeof(T));
}

static void serialize(std::string& buf, const std::string& str) {

    buf.reserve(buf.size() + str.size() + 4);
    serialize_integer(buf, str.size());
    buf += str;
}

template <typename T>
void serialize_message(std::string& res, const T& msg) {

    /// TODO: use binary / base64 representation for pk
    res += msg.pub_key;
    serialize(res, msg.hash);
    serialize(res, msg.data);
    serialize_integer(res, msg.ttl);
    serialize_integer(res, msg.timestamp);
    serialize(res, msg.nonce);

    LOKI_LOG(trace, "serialized message: {}", msg.data);
}

template void serialize_message(std::string& res, const message_t& msg);
template void serialize_message(std::string& res, const Item& msg);

template <typename T>
std::vector<std::string> serialize_messages(const std::vector<T>& msgs) {

    std::vector<std::string> res;

    std::string buf;

    constexpr size_t BATCH_SIZE = 500000;

    for (const auto& msg : msgs) {
        serialize_message(buf, msg);
        if (buf.size() > BATCH_SIZE) {
            res.push_back(std::move(buf));
            buf.clear();
        }
    }

    if (!buf.empty()) {
        res.push_back(std::move(buf));
    }

    return res;
}

template std::vector<std::string>
serialize_messages(const std::vector<message_t>& msgs);

template std::vector<std::string>
serialize_messages(const std::vector<Item>& msgs);

struct string_view {

    std::string::const_iterator it;
    const std::string::const_iterator it_end;

    string_view(const std::string& data)
        : it(data.begin()), it_end(data.end()) {}

    size_t size() { return it_end - it; }

    bool empty() { return it_end <= it; }
};

static std::optional<std::string> deserialize_string(string_view& slice,
                                                     size_t len) {

    if (slice.size() < len) {
        return std::nullopt;
    }

    const auto res = std::string(slice.it, slice.it + len);
    slice.it += len;

    return res;
}

static std::optional<std::string> deserialize_string(string_view& slice) {

    if (slice.size() < sizeof(size_t))
        return std::nullopt;

    const auto len =
        deserialize_integer<size_t>(slice.it); // already increments `it`!

    return deserialize_string(slice, len);
}

static std::optional<uint64_t> deserialize_uint64(string_view& slice) {

    if (slice.size() < sizeof(uint64_t))
        return std::nullopt;

    const auto res = deserialize_integer<uint64_t>(slice.it);

    return res;
}

std::vector<message_t> deserialize_messages(const std::string& blob) {

    LOKI_LOG(trace, "=== Deserializing ===");

    std::vector<message_t> result;

    string_view slice{blob};

    while (!slice.empty()) {

        /// Deserialize PK
        auto pk = deserialize_string(slice, loki::get_user_pubkey_size());
        if (!pk) {
            LOKI_LOG(debug, "Could not deserialize pk");
            return {};
        }

        /// Deserialize Hash
        auto hash = deserialize_string(slice);
        if (!hash) {
            LOKI_LOG(debug, "Could not deserialize hash");
            return {};
        }

        /// Deserialize Data
        auto data = deserialize_string(slice);
        if (!data) {
            LOKI_LOG(debug, "Could not deserialize data");
            return {};
        }

        /// Deserialize TTL
        auto ttl = deserialize_uint64(slice);
        if (!ttl) {
            LOKI_LOG(debug, "Could not deserialize ttl");
            return {};
        }

        /// Deserialize Timestamp
        auto timestamp = deserialize_uint64(slice);
        if (!timestamp) {
            LOKI_LOG(debug, "Could not deserialize timestamp");
            return {};
        }

        /// Deserialize Nonce
        auto nonce = deserialize_string(slice);
        if (!nonce) {
            LOKI_LOG(debug, "Could not deserialize nonce");
            return {};
        }

        LOKI_LOG(trace, "Deserialized data: {}", *data);

        LOKI_LOG(trace, "pk: {}, msg: {}", *pk, *data);

        result.push_back({*pk, *data, *hash, *ttl, *timestamp, *nonce});
    }

    LOKI_LOG(trace, "=== END ===");

    return result;
}

} // namespace loki
