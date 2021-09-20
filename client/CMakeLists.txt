add_executable(client client.c)
target_link_libraries(client OpenSSL::SSL)

install(TARGETS client DESTINATION bin)
