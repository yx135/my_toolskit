// tests/logger_test.cpp
#include <Logger/Logger.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <db/sqlite3/CppSQLite3/CppSQLite3.h>
#include <db/mysql/MysqlCapi.h>
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
void sqlite3_test() {
    CppSQLite3DB db;
    db.open("/home/useryx/workspace/cpp/my_toolskit/build/bin/test.db");
    if (db.isOpen()) {
        std::cout << "sqlite3 open success" << std::endl;
        db.execDML("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)");
    } else {
        std::cout << "sqlite3 open failed" << std::endl;
    }
    db.close();
}

void mysql_test() {
    Connection mysql;
    bool conn=  mysql.connect("mysql-yxmysql.c.aivencloud.com", 19894, "avnadmin", "AVNS_icoPVWCDqQgoAM4nCH1", "one-api-dev");
    if (conn) {
        std::cout << "mysql open success" << std::endl;
    } else {
        std::cout << "mysql open failed" << std::endl;
    }
}

int main() {
    // 测试代码
    logger_test();
    sqlite3_test();
    mysql_test();

    return 0;
}