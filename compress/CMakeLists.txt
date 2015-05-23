project(compress)

find_package(ZLIB REQUIRED)
if(NOT ZLIB_FOUND)
    message(FATAL_ERROR "Zlib not found")
endif()

include_directories(${ZLIB_INCLUDE_DIRS})
add_library(compress STATIC compress.cpp)
target_link_libraries(compress ${ZLIB_LIBRARIES})
