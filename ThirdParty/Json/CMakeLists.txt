cmake_minimum_required(VERSION 3.15 FATAL_ERROR)	
project(NlohmannJSON LANGUAGES CXX)

set(JSON_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/nlohmann/include" CACHE INTERNAL "")

ibox_install_third()
