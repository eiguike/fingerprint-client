cmake_minimum_required(VERSION 3.0)

project(fingerprint-client C)

add_library(Server STATIC library/server.c)
add_library(ServerHTTP STATIC library/protocols/http_protocol.c)
add_library(ServerImage STATIC library/protocols/image_protocol.c)
add_library(Device STATIC library/device.c)
add_library(Fingerprint STATIC library/fingerprint.c)

include_directories("./include")

set(SOURCE_FILES main.c)
add_executable(fingerprint-client ${SOURCE_FILES})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/www
      DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(Server websockets)
target_link_libraries(Server ServerHTTP)
target_link_libraries(Server ServerImage)

target_link_libraries(Fingerprint curl)
target_link_libraries(Fingerprint cjson)
target_link_libraries(Fingerprint crypto)
target_link_libraries(Fingerprint fprint)

target_link_libraries(Device Fingerprint)
if(WIRINGPI)
  target_link_libraries(Device wiringPi)
endif()

target_link_libraries(fingerprint-client Device)
target_link_libraries(fingerprint-client Server)
target_link_libraries(fingerprint-client pthread)

install(TARGETS fingerprint-client DESTINATION /bin)
