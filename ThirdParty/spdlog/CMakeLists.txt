cmake_minimum_required(VERSION 3.15 FATAL_ERROR)	
project(SpdLog LANGUAGES CXX)

set(SPDLOG_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include" CACHE INTERNAL "")

ibox_install_third()
