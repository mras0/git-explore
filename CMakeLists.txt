cmake_minimum_required(VERSION 2.8)
project(git-explore)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1) # For YouCompleteMe support (see https://github.com/Valloric/YouCompleteMe)

enable_testing()
# http://stackoverflow.com/questions/16158091/cmake-setting-an-environmental-variable-for-ctest-or-otherwise-getting-failed
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --force-new-ctest-process --output-on-failure)

set(common_flags "-Wall -Wextra -pthread -g3")

set(use_asan  TRUE  CACHE BOOL "Use address sanitizier")
set(use_tsan  FALSE CACHE BOOL "Use thread sanitizier")
set(use_ubsan TRUE  CACHE BOOL "Use undefined behavior sanitizier")

if (use_asan)
    message("Using address sanitizer")
    set(common_flags "${common_flags} -fsanitize=address")
endif()
if (use_tsan)
    message("Using thread sanitizer")
    set(common_flags "${common_flags} -fsanitize=thread")
endif()
if (use_ubsan)
    message("Using undefined behavior sanitizer")
    set(common_flags "${common_flags} -fsanitize=undefined")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${common_flags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${common_flags}")

add_subdirectory(digest)
add_subdirectory(compress)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(git-explore git-explore.cpp)
target_link_libraries(git-explore digest compress)

find_program(HAS_CTAGS ctags)
if (HAS_CTAGS)
    message("ctags found")

    set_source_files_properties(tags PROPERTIES GENERATED true)
    add_custom_target(tags
        COMMAND ctags -R --c++-kinds=+p --fields=+iaS --extra=+q --exclude=build* ${CMAKE_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    add_dependencies(git-explore tags)
endif()
