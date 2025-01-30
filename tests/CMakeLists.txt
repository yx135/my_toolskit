set(HEARDER_DIR ${PROJECT_SOURCE_DIR}/include)

# 添加测试可执行文件
add_executable(test test.cpp)

# 添加头文件搜索路径
target_include_directories(test PRIVATE 
    ${HEARDER_DIR}
    ${PROJECT_SOURCE_DIR}/ThirdParty/spdlog/include
)

# 链接必要的库
target_link_libraries(test PRIVATE 
    my_toolskit
    #spdlog::spdlog
    fmt::fmt
)

# 设置输出目录
set_target_properties(test
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)