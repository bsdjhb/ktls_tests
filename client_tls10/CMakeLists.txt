add_executable(client_tls10 client_tls10.c)
target_link_libraries(client_tls10 OpenSSL::SSL)

install(TARGETS client_tls10 DESTINATION bin)
