project(digest)

add_library(digest STATIC digest.cpp sha1.c)

add_executable(digest_test digest_test.cpp)
target_link_libraries(digest_test digest)
add_test(digest_test digest_test)
