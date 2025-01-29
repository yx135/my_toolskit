// tests/logger_test.cpp
#include <Logger/Logger.h>
#include <nlohmann/json.hpp>
#include <iostream>
using namespace my_toolskit;
using json = nlohmann::json;

void logger_test() {
    // 创建配置
    json config = {
        {"logger", {
            {"logFileFullName", "/home/useryx/workspace/cpp/my_toolskit/build/bin/test_logger.txt"},
            {"logFileMaxSize", 1},  // 1MB
            {"logFilesCount", 2},
            {"logPattern", "[%Y-%m-%d %H:%M:%S.%e]<%L>%v"},
            {"logOnConsole", 1},
            {"logLevel", "INFO"}
        }}
    };

    // 初始化Logger
    auto logger = Logger::getInstance();
    if (logger->initialize(config) != 0) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return;
    }

    // 测试日志
    logger->info("Hello, World!");
    logger->debug("This is a debug message");
    logger->error("This is an error message");
}

int main() {
    // 测试代码
    logger_test();
    return 0;
}