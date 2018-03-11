cmake_minimum_required(VERSION 3.0)

project(fingerprint-client C)

add_library(Server STATIC library/server.c)
add_library(ServerHTTP STATIC library/protocols/http_protocol.c)

include_directories("./include")

set(SOURCE_FILES main.c)
add_executable(fingerprint-client ${SOURCE_FILES})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(Server websockets)
target_link_libraries(Server ServerHTTP)
target_link_libraries(fingerprint-client Server)

install(TARGETS fingerprint-client DESTINATION /bin)


