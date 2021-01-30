#pragma once

#include <algorithm>
#include <array>
#include <random>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace util {

bool validateTTL(uint64_t ttlInt);
// Convert ttl string into uint64_t, return bool for success/fail
bool parseTTL(const std::string& ttlString, uint64_t& ttl);

bool validateTimestamp(uint64_t timestamp, uint64_t ttl);
// Convert timestamp string into uint64_t, return bool for success/fail
bool parseTimestamp(const std::string& timestampString, const uint64_t ttl,
                    uint64_t& timestamp);

// Get current time in milliseconds
uint64_t get_time_ms();

// adapted from Gyuanxnet llarp/encode.hpp
// from  https://en.wikipedia.org/wiki/Base32#z-base-32
static const char zbase32_alpha[] = {'y', 'b', 'n', 'd', 'r', 'f', 'g', '8',
                                     'e', 'j', 'k', 'm', 'c', 'p', 'q', 'x',
                                     'o', 't', '1', 'u', 'w', 'i', 's', 'z',
                                     'a', '3', '4', '5', 'h', '7', '6', '9'};

static const std::unordered_map<char, uint8_t> zbase32_reverse_alpha = {
    {'y', 0},  {'b', 1},  {'n', 2},  {'d', 3},  {'r', 4},  {'f', 5},  {'g', 6},
    {'8', 7},  {'e', 8},  {'j', 9},  {'k', 10}, {'m', 11}, {'c', 12}, {'p', 13},
    {'q', 14}, {'x', 15}, {'o', 16}, {'t', 17}, {'1', 18}, {'u', 19}, {'w', 20},
    {'i', 21}, {'s', 22}, {'z', 23}, {'a', 24}, {'3', 25}, {'4', 26}, {'5', 27},
    {'h', 28}, {'7', 29}, {'6', 30}, {'9', 31}};

std::string base64_decode(std::string const& data);

std::string base64_encode(std::string const& s);

/// adapted from i2pd
template <typename Container, typename stack_t>
const char* base32z_encode(const Container& value, stack_t& stack) {
    size_t ret = 0, pos = 1;
    uint32_t bits = 8, tmp = value[0];
    size_t len = value.size();
    while (ret < sizeof(stack) && (bits > 0 || pos < len)) {
        if (bits < 5) {
            if (pos < len) {
                tmp <<= 8;
                tmp |= value[pos] & 0xFF;
                pos++;
                bits += 8;
            } else // last byte
            {
                tmp <<= (5 - bits);
                bits = 5;
            }
        }

        bits -= 5;
        int ind = (tmp >> bits) & 0x1F;
        if (ret < sizeof(stack)) {
            stack[ret] = zbase32_alpha[ind];
            ret++;
        } else
            return nullptr;
    }
    return &stack[0];
}

template <int a, int b>
static size_t decode_size(size_t sz) {
    auto d = div(sz, a);
    if (d.rem)
        d.quot++;
    return b * d.quot;
}

[[maybe_unused]] static size_t base32_decode_size(size_t sz) {
    return decode_size<5, 8>(sz);
}

template <typename Stack, typename V>
bool base32z_decode(const Stack& stack, V& value) {
    int tmp = 0, bits = 0;
    size_t ret = 0;
    size_t len = base32_decode_size(value.size());
    size_t outLen = value.size();
    for (size_t i = 0; i < len; i++) {
        char ch = stack[i];
        if (ch) {
            auto itr = zbase32_reverse_alpha.find(ch);
            if (itr == zbase32_reverse_alpha.end())
                return false;
            ch = itr->second;
        } else {
            return ret == outLen;
        }
        tmp |= ch;
        bits += 5;
        if (bits >= 8) {
            if (ret >= outLen)
                return false;
            value[ret] = tmp >> (bits - 8);
            bits -= 8;
            ret++;
        }
        tmp <<= 5;
    }
    return true;
}

std::string hex_to_base32z(const std::string& src);

std::string hex_to_bytes(const std::string& hex);

// Creates a hex string from a character sequence.
template <typename It>
std::string as_hex(It begin, It end) {
    constexpr std::array<char, 16> lut{{'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e',
                                        'f'}};
    std::string hex;
    using std::distance;
    hex.reserve(distance(begin, end) * 2);
    while (begin != end) {
        char c = *begin;
        hex += lut[(c & 0xf0) >> 4];
        hex += lut[c & 0x0f];
        ++begin;
    }
    return hex;
}

template <typename String>
inline std::string as_hex(const String& s) {
    using std::begin;
    using std::end;
    return as_hex(begin(s), end(s));
}

/// Returns a reference to a randomly seeded, thread-local RNG.
std::mt19937_64& rng();

/// Returns a random number from [0, n) using `rng()`
uint64_t uniform_distribution_portable(uint64_t n);

/// Returns a random number from [0, n); (copied from gyuanxd)
uint64_t uniform_distribution_portable(std::mt19937_64& mersenne_twister,
                                       uint64_t n);

/// Return the open file limit (-1 on failure)
int get_fd_limit();

} // namespace util
