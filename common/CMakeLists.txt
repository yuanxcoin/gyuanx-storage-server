cmake_minimum_required(VERSION 3.1)

add_definitions(-DSPDLOG_COMPILED_LIB)

add_library(common STATIC
    src/gyuanx_logger.cpp
)


find_package(Boost
    REQUIRED
    filesystem
)

set_property(TARGET common PROPERTY CXX_STANDARD 17)
set_property(TARGET common PROPERTY CXX_STANDARD_REQUIRED TRUE)

gyuanx_add_subdirectory(../vendors/spdlog spdlog)

target_link_libraries(common PUBLIC spdlog::spdlog ${Boost_LIBRARIES})
target_include_directories(common PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${Boost_INCLUDE_DIRS}
)
