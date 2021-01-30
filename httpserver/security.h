#pragma once

#include <string>

#include <boost/filesystem/path.hpp>

namespace gyuanx {

struct gyuanxd_key_pair_t;

class Security {
  public:
    Security(const gyuanxd_key_pair_t& key_pair,
             const boost::filesystem::path& base_path);

    std::string base64_sign(const std::string& body);
    void generate_cert_signature();
    std::string get_cert_signature() const;

  private:
    const gyuanxd_key_pair_t& key_pair_;
    std::string cert_signature_;
    boost::filesystem::path base_path_;
};
} // namespace gyuanx