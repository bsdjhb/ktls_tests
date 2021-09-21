add_executable(client client.c bio_delay.c)
target_link_libraries(client OpenSSL::SSL)

install(TARGETS client DESTINATION bin)
