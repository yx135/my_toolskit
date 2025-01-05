# 添加测试可执行文件
add_executable(test_algorithms test.cpp)

# 设置包含目录
target_include_directories(test_algorithms 
    PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
)

# 链接主库
target_link_libraries(test_algorithms
    PRIVATE
    my_toolskit
    ${ZLIB_LIBRARIES}
)

# 设置输出路径
set_target_properties(test_algorithms
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/tests"
) 