cmake_minimum_required(VERSION 3.5)

project(08.homework)

if (MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-g -Wall -Wextra -pedantic -Werror)
endif()



add_executable(topk topk.cpp)
set_target_properties(topk PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
target_link_libraries(topk Threads::Threads)
