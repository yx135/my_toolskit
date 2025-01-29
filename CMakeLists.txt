cmake_minimum_required(VERSION 3.10)
project(my_toolskit VERSION 1.0)

# 添加 cmake 模块路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置动态库的输出路径
#${CMAKE_BINARY_DIR} 指的是构建目录（build directory），也就是你执行 cmake 命令时的目标目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 设置动态库的版本信息
set(MY_TOOLSKIT_VERSION_MAJOR 1)
set(MY_TOOLSKIT_VERSION_MINOR 0)
set(MY_TOOLSKIT_VERSION_PATCH 0)
set(MY_TOOLSKIT_VERSION "${MY_TOOLSKIT_VERSION_MAJOR}.${MY_TOOLSKIT_VERSION_MINOR}.${MY_TOOLSKIT_VERSION_PATCH}")

# 查找 MySQL/MariaDB
find_package(MySQL REQUIRED)
find_package(ZLIB REQUIRED)

# 查找 spdlog
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} "${PROJECT_SOURCE_DIR}/ThirdParty/spdlog")
find_package(spdlog REQUIRED)
if(NOT spdlog_FOUND)
    message(FATAL_ERROR "spdlog not found")
endif()

# 查找 fmt 库
find_package(fmt REQUIRED)
if(NOT fmt_FOUND)
    message(FATAL_ERROR "fmt not found")
endif()

# 添加头文件目录搜索路径
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/ThirdParty/Json/nlohmann/include
    ${spdlog_INCLUDE_DIR}
    ${MYSQL_INCLUDE_DIR}
)

# 手动指定源文件
set(SOURCES
   # src/DBManager/DBManager.cpp
   # src/db/sqlite3/CppSQLite3/CppSQLite3.cpp
    src/Logger/Logger.cpp
   # src/Date/Date.cpp
   # src/Network/Network.cpp
   # src/Timer/Timer.cpp
   # src/Threading/Threading.cpp
    src/Algorithms/Algorithms.cpp
    # src/TcpServer/TcpServer.cpp
    # src/TcpClient/TcpClient.cpp
    # src/HttpClient/HttpClient.cpp
    # src/HTTPSClient/HTTPSClient.cpp
    # src/HtMqttClient/HtMqttClient.cpp
    # src/MediaPlayer/MediaPlayer.cpp
    # src/OpenSSL/OpenSSL.cpp
    # src/StreamDataBuffer/StreamDataBuffer.cpp
    # src/Uart/Uart.cpp
    src/db/mysql/MysqlCapi.cpp
)

# 手动指定头文件
set(HEADERS
     include/Error.h
    # include/DBManager/DBManager.h
    # include/db/sqlite3/CppSQLite3/CppSQLite3.h
     include/Logger/Logger.h
    # include/Date/Date.h
    # include/Network/Network.h
    # include/Timer/Timer.h
    # include/Threading/Threading.h
     include/Algorithms/Algorithms.h
    # include/TcpServer/TcpServer.h
    # include/TcpClient/TcpClient.h
    # include/HttpClient/HttpClient.h
    # include/HTTPSClient/HTTPSClient.h
    # include/HtMqttClient/HtMqttClient.h
    # include/MediaPlayer/MediaPlayer.h
    # include/OpenSSL/OpenSSL.h
    # include/StreamDataBuffer/StreamDataBuffer.h
    # include/Uart/Uart.h
    include/db/mysql/MysqlCapi.h
)

# 创建动态库目标
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# 设置动态库的版本
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${MY_TOOLSKIT_VERSION}
    SOVERSION ${MY_TOOLSKIT_VERSION_MAJOR}
)

# 链接依赖库
target_link_libraries(${PROJECT_NAME} PRIVATE spdlog::spdlog)

# 链接依赖库
target_link_libraries(${PROJECT_NAME} PRIVATE ${MYSQL_LIBRARY} ${ZLIB_LIBRARIES})
# 添加示例目录
# Sadd_subdirectory(examples)

# 添加测试目录
add_subdirectory(tests)

# 安装规则
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/
        DESTINATION include)

# 输出调试信息
message(STATUS "MYSQL_INCLUDE_DIR: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MYSQL_LIBRARY: ${MYSQL_LIBRARY}")
message(STATUS "ZLIB_LIBRARIES: ${ZLIB_LIBRARIES}")
message(STATUS "spdlog version: ${spdlog_VERSION}")
message(STATUS "spdlog include dir: ${spdlog_INCLUDE_DIR}")
message(STATUS "spdlog libraries: ${spdlog_LIBRARIES}")
