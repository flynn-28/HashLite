cmake_minimum_required(VERSION 3.10)
project(HashLite)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(HashLite STATIC src/HashLite.cpp src/SHA1.cpp src/SHA224.cpp src/SHA256.cpp src/SHA384.cpp src/SHA512.cpp src/MD5.cpp src/CRC8.cpp src/CRC16.cpp src/CRC32.cpp)

target_include_directories(HashLite PUBLIC include)

set_property(TARGET HashLite PROPERTY POSITION_INDEPENDENT_CODE ON)
