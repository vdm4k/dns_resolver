cmake_minimum_required(VERSION 3.3.2)
project(dns_resolver_examples VERSION 0.9.0 DESCRIPTION "examples for libev_wrapper")

find_package(Threads REQUIRED)

add_executable(simple_test main.cpp )

target_link_libraries(simple_test PUBLIC Threads::Threads dns_resolver::dns_resolver)
