cmake_minimum_required(VERSION 3.16)
project(linux_behavior_detector VERSION 0.1.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(bdetect src/bdetect.cpp)
target_include_directories(bdetect PRIVATE include)
target_link_libraries(bdetect PRIVATE OpenSSL::Crypto Threads::Threads)
target_compile_options(bdetect PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(CTest)
if(BUILD_TESTING)
    add_test(NAME behavior-fixtures COMMAND ${CMAKE_COMMAND} -E env BIN_DIR=$<TARGET_FILE_DIR:bdetect> ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh)
endif()

option(BDETECT_BUILD_FUZZER "Build the optional Clang libFuzzer JSON parser target" OFF)
if(BDETECT_BUILD_FUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BDETECT_BUILD_FUZZER requires Clang with libFuzzer support")
    endif()
    add_executable(bdetect-json-fuzz tests/fuzz_json.cpp)
    target_include_directories(bdetect-json-fuzz PRIVATE include)
    target_compile_options(bdetect-json-fuzz PRIVATE
        -O1 -g -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined)
    target_link_options(bdetect-json-fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
