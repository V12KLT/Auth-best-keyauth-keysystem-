cmake_minimum_required(VERSION 3.10)
project(KeyAuth LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(keyauth keyauth.cpp)

target_link_libraries(keyauth PRIVATE
    ws2_32
    secur32
    bcrypt
    crypt32
    advapi32
)
