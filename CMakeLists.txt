cmake_minimum_required(VERSION 3.31)
project(crypto-handler)

set(CH_PROJECT_NAME crypto-handler)
set(CMAKE_CXX_STANDARD 23)

# add dependencies
include(cmake/dependencies.cmake)


add_library(${CH_PROJECT_NAME} STATIC
        src/CryptoHandler.cpp)

target_include_directories(${CH_PROJECT_NAME}
        PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include/public"
        PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/private")
target_link_libraries(${CH_PROJECT_NAME} jlizard::byte-ao)

add_library(jlizard::crypto-handler ALIAS ${CH_PROJECT_NAME})

enable_testing()
include(cmake/tests.cmake)