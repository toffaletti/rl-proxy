project(rl-proxy)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(fw)
include(${CMAKE_CURRENT_SOURCE_DIR}/fw/cmake/fw.cmake)

add_executable(rl-proxy rl-proxy.cc)
target_link_libraries(rl-proxy fw http uri boost_program_options jansson)