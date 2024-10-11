cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 20)

project(double-ratchet)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} main.cpp ChatClient.cpp
        DoubleRatchet.cpp
        KDF.cpp
        KeyManager.cpp
        Utils.h
        Types.h
)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)