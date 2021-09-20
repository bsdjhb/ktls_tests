add_executable(server server.c)
target_link_libraries(server OpenSSL::SSL)

install(TARGETS server DESTINATION bin)
