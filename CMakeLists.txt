cmake_minimum_required(VERSION 3.14.0)
project(dns_resolver VERSION 0.9.1 DESCRIPTION "network library")

set(H_FILES
    include/dns/resolver.h
    include/dns/query.h
    include/dns/client.h
)

set(CPP_FILES
    source/dns/resolver.cpp
    source/dns/query.cpp
    source/dns/client.cpp
)

include("${PROJECT_SOURCE_DIR}/third_party/libev_wrapper.cmake")
include("${PROJECT_SOURCE_DIR}/third_party/network_protocols.cmake")
include("${PROJECT_SOURCE_DIR}/third_party/c_ares.cmake")

add_library(${PROJECT_NAME} ${CPP_FILES} ${H_FILES})
add_library(bro::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
add_library(dns_resolver::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE  -Wall -Wextra -Wpedantic -Wno-vla -Wno-unused-local-typedefs)

# TODO: maybe we need to add only not secure (without SSL)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC
    $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

#sanitizer
option(WITH_SANITIZER "Enable address sanitizer" OFF)

if(WITH_SANITIZER)
    target_compile_options(${PROJECT_NAME} INTERFACE -fsanitize=address -fPIC)
    target_link_options(${PROJECT_NAME} INTERFACE -fsanitize=address)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC bro::libev_wrapper bro::network_protocols c-ares)

#examples
option(WITH_EXAMPLES "Build examples" OFF)
if(WITH_EXAMPLES)
    add_subdirectory(examples)
endif()
