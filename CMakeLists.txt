cmake_minimum_required(VERSION 3.20)
project(Sential)

set(CMAKE_CXX_STANDARD 17)



set(PCAP_INCLUDE_DIR "${BASE_DIR}/Include")
set(PCAP_LIB_DIR "${BASE_DIR}/Lib/x64")

include_directories(${PCAP_INCLUDE_DIR})
link_directories(${PCAP_LIB_DIR})

add_executable(Sential main.cpp sqlite3.c)

target_link_libraries(Sential wpcap Packet ws2_32)