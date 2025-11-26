add_executable(ch_unit_tests tests/unit_tests.cpp)
target_link_libraries(ch_unit_tests PRIVATE jlizard::crypto-handler)
#target_include_directories(byteao_unit_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")

add_test(NAME "Crypto handler Unit Tests" COMMAND ch_unit_tests)