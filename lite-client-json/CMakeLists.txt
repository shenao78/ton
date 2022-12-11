cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

set(LITE_CLIENT_JSON_HEADERS lite-client-json.h)
set(LITE_CLIENT_JSON_SOURCE lite-client-json.cpp)

add_library(lite-client-json SHARED ${LITE_CLIENT_JSON_SOURCE})

target_link_libraries(lite-client-json PRIVATE tl_lite_api_json)