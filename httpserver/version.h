#pragma once

#include "gyuanx_logger.h"

#include <iostream>

#define VERSION_MAJOR 2
#define VERSION_MINOR 0
#define VERSION_PATCH 7

#define GYUANX_STRINGIFY2(val) #val
#define GYUANX_STRINGIFY(val) GYUANX_STRINGIFY2(val)

#define VERSION_MAJOR_STR GYUANX_STRINGIFY(VERSION_MAJOR)
#define VERSION_MINOR_STR GYUANX_STRINGIFY(VERSION_MINOR)
#define VERSION_PATCH_STR GYUANX_STRINGIFY(VERSION_PATCH)

#ifndef STORAGE_SERVER_VERSION_STRING
#define STORAGE_SERVER_VERSION_STRING                                          \
    VERSION_MAJOR_STR "." VERSION_MINOR_STR "." VERSION_PATCH_STR
#endif

#ifndef STORAGE_SERVER_GIT_HASH_STRING
#define STORAGE_SERVER_GIT_HASH_STRING "?"
#endif

#ifndef STORAGE_SERVER_BUILD_TIME
#define STORAGE_SERVER_BUILD_TIME "?"
#endif

inline std::string version_info() {
    return fmt::format(
        "Gyuanx Storage Server v{}\n git commit hash: {}\n build time: {}\n",
        STORAGE_SERVER_VERSION_STRING, STORAGE_SERVER_GIT_HASH_STRING,
        STORAGE_SERVER_BUILD_TIME);
}
inline void print_version() { GYUANX_LOG(info, "{}", version_info()); }
