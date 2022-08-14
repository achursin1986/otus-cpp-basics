cmake_minimum_required(VERSION 3.10)

project(container CXX)

add_executable(container
    serial_container.hpp
    l1_linked_container.hpp
    l2_linked_container.hpp
    main.cpp
)


if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR
    CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(container PRIVATE
        -g
        -Wall
        -Wextra
        -Werror
        -pedantic
    )
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(container PRIVATE
        /EHsc
        /W4
        /WX
    )
endif()

target_compile_features(container PUBLIC cxx_std_17)
