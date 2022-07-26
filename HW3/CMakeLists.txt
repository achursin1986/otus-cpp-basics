cmake_minimum_required(VERSION 3.5)

project(03.guess_the_number)

set(EXECUTABLE_OUTPUT_PATH "build")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -Werr -Wextra -pedantic")

add_executable(guess_the_number 
    guess_the_number.cpp
    file.cpp
    game.cpp
    func.h
    struct.h
)

set_target_properties(guess_the_number PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)



