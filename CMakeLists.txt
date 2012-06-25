project(rl-proxy)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(libten)
include(${CMAKE_CURRENT_SOURCE_DIR}/libten/cmake/ten.cmake)

add_executable(rl-proxy rl-proxy.cc)
target_link_libraries(rl-proxy ten boost_program_options jansson)

add_executable(rl-keygen rl-keygen.cc)
target_link_libraries(rl-keygen ten boost_program_options)

add_executable(credit-client credit-client.cc)
target_link_libraries(credit-client ten boost_program_options)

add_executable(credit-server credit-server.cc)
target_link_libraries(credit-server ten boost_program_options)

add_library(keygen SHARED keygen.cc)
target_link_libraries(keygen ten)

install(TARGETS rl-proxy DESTINATION bin)
install(TARGETS rl-keygen DESTINATION bin)
install(TARGETS credit-server DESTINATION bin)
install(TARGETS credit-client DESTINATION bin)
install(TARGETS keygen DESTINATION lib)
