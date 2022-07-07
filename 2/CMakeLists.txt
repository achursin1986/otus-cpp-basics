cmake_minimum_required(VERSION 3.5)

project(01.hello_world)

set(EXECUTABLE_OUTPUT_PATH "build")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -Werr -Wextra -pedantic")

add_executable(hello_world 
    hello_world.cpp
    example.cpp
    example.h
    move_me_out.h
    move_me_out.cpp
)

set_target_properties(hello_world PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)



