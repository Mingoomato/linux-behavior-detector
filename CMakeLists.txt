cmake_minimum_required(VERSION 3.16)
project(linux_behavior_detector VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(bdetect src/bdetect.cpp)
target_include_directories(bdetect PRIVATE include)
target_compile_options(bdetect PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME behavior-fixtures COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
endif()
