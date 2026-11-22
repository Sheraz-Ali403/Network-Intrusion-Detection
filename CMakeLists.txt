#[[
cmake -S . -B build-ucrt64
Build only your IDS:
cmake --build build-ucrt64 --target Intrusion_Detection_System


Build only the HashTable test:
cmake --build build-ucrt64 --target test_hash_table


Run the HashTable test:
ctest --test-dir build-ucrt64 -R HashTableTest --output-on-failure


Run all registered tests:
ctest --test-dir build-ucrt64 --output-on-failure
]]

cmake_minimum_required(VERSION 3.20)

project(Intrusion_Detection_System)

set(CMAKE_CXX_STANDARD 20)

# Actual IDS application
add_executable  (Intrusion_Detection_System
    src/main.cpp
    src/pcapHandler.cpp
    src/data_hash_table.cpp
    src/rate_table.cpp
    src/aho_corasick.cpp
    src/cidr_blacklist.cpp
)
target_include_directories(Intrusion_Detection_System PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

find_package(PcapPlusPlus CONFIG REQUIRED)

target_link_libraries(Intrusion_Detection_System
    PRIVATE
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Packet++
    PcapPlusPlus::Common++
)

# Hash table unit tests
add_executable( test_hash_table

    tests/test_hash_table.cpp
    src/data_hash_table.cpp

)
target_include_directories(test_hash_table PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
find_package(PcapPlusPlus CONFIG REQUIRED)

target_link_libraries(test_hash_table
    PRIVATE
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Packet++
    PcapPlusPlus::Common++
)

#Register tests with CTest
enable_testing()

add_test(
    NAME HashTableTest
    COMMAND test_hash_table
)

# rate table test
add_executable( rate_table_table

    tests/test_rate_table.cpp
    src/rate_table.cpp

)
target_include_directories(rate_table_table PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
find_package(PcapPlusPlus CONFIG REQUIRED)

target_link_libraries(rate_table_table
    PRIVATE
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Packet++
    PcapPlusPlus::Common++
)

#Register tests with CTest
enable_testing()

add_test(
    NAME RateTableTest
    COMMAND rate_table_table
)
