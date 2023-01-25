cmake_minimum_required(VERSION 3.10)

project(isis-mocker CXX)
set(PATCH_VERSION "4" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION 0.0.${PATCH_VERSION})
project(isis-mocker VERSION ${PROJECT_VERSION})

configure_file(version.h.in include/version.h)

add_executable(isis-mocker
    src/main.cpp
)
add_executable(tests
    src/tests.cpp
)

add_executable(isis-mocker-debug
    src/main.cpp
)
add_library(isis-mocker-version src/get_version.cpp)
target_include_directories(isis-mocker-version PRIVATE include)


target_include_directories(isis-mocker PRIVATE include)
set_target_properties(isis-mocker PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
find_package(Boost COMPONENTS thread REQUIRED)
target_link_libraries(isis-mocker Threads::Threads)
target_link_libraries(isis-mocker Boost::thread)
target_link_libraries(isis-mocker isis-mocker-version)


target_include_directories(isis-mocker-debug PRIVATE include)
set_target_properties(isis-mocker-debug PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_link_libraries(isis-mocker-debug Threads::Threads)
target_link_libraries(isis-mocker-debug Boost::thread)
target_link_libraries(isis-mocker-debug isis-mocker-version)


target_compile_options(isis-mocker PRIVATE
        -Wall
        -Werror
        -Wextra
        -pedantic
    )
set_target_properties(isis-mocker PROPERTIES LINK_FLAGS_RELEASE -s)
target_compile_options(isis-mocker-debug PRIVATE
        -g
        -Wall
        -Werror
        -Wextra
        -pedantic
    )
target_compile_definitions(isis-mocker-debug PRIVATE DEBUG)
target_include_directories(tests PRIVATE include)
target_include_directories(isis-mocker-version PRIVATE include)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
target_link_libraries(tests gmock gmock_main gtest pthread)

install(TARGETS isis-mocker RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT achursin@juniper.net)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS YES)

include(CPack)


