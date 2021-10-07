cmake_minimum_required(VERSION 3.10)

project(KTLSTests)

add_compile_options(-Wall -Werror)

find_package(OpenSSL REQUIRED)

add_subdirectory(client)
add_subdirectory(client_tls10)
add_subdirectory(server)
