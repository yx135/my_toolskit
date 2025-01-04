cmake_minimum_required(VERSION 3.10)
project(my_toolskit VERSION 1.0)

# 添加 cmake 模块路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置动态库的输出路径
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 设置动态库的版本信息
set(MY_TOOLSKIT_VERSION_MAJOR 1)
set(MY_TOOLSKIT_VERSION_MINOR 0)
set(MY_TOOLSKIT_VERSION_PATCH 0)
set(MY_TOOLSKIT_VERSION "${MY_TOOLSKIT_VERSION_MAJOR}.${MY_TOOLSKIT_VERSION_MINOR}.${MY_TOOLSKIT_VERSION_PATCH}")

# 查找 MySQL/MariaDB
find_package(MySQL REQUIRED)
include_directories(${MYSQL_INCLUDE_DIR})

# 添加头文件目录
include_directories(${PROJECT_SOURCE_DIR}/include)

# 查找源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h" "include/*.hpp")

# 创建动态库目标
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# 设置动态库的版本
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${MY_TOOLSKIT_VERSION}
    SOVERSION ${MY_TOOLSKIT_VERSION_MAJOR}
)

# 链接依赖库
target_link_libraries(${PROJECT_NAME} ${MYSQL_LIBRARY})

# 安装规则
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(DIRECTORY include/
        DESTINATION include)
