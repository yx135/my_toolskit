cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(libopenssl LANGUAGES CXX)

if(ARCHITECTURE STREQUAL "X64")
set(SSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libopenssl/include" CACHE INTERNAL "")
set(SSL_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libopenssl/lib" CACHE INTERNAL "")
endif()

ibox_install_third()
