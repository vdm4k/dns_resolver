cmake_minimum_required(VERSION 3.3.2)
project(dns_resolver_example VERSION 1.0.0 DESCRIPTION "dns resolver example")

find_package(Threads REQUIRED)

add_executable(${PROJECT_NAME} main.cpp )

target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads dns_resolver::dns_resolver)
