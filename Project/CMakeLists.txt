cmake_minimum_required(VERSION 3.10)

project(repl CXX)

add_executable(repl
    src/main.cpp
)
add_executable(tests
    src/tests.cpp
)

target_include_directories(repl PRIVATE include)
set_target_properties(repl PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
find_package(Boost COMPONENTS thread REQUIRED)
target_link_libraries(repl Threads::Threads)
target_link_libraries(repl Boost::thread)
target_compile_options(repl PRIVATE
        -g
        -Wall
        -Wextra
        -Werror
        -pedantic
    )
target_include_directories(tests PRIVATE include)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
target_link_libraries(tests gmock gmock_main gtest pthread)
