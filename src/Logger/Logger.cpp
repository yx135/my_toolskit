#include <iostream>
#include <string>
#include "Logger/Logger.h"

#include "spdlog/sinks/stdout_sinks.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/async.h"

namespace my_toolskit {

Logger::LoggerLevel getLevelFromString(const std::string& level);

const uint32_t MAX_LOG_FILE_SIZE = 1;  /// the unit is mB
const uint32_t MAX_LOG_FILE_NUM = 2;

const std::string CONSOLE_LOGGER_NAME = "consoleLogger";
const std::string ROTATE_LOGGER_NAME = "rotateLogger";
const std::string ROTATE_LOG_FULL_NAME = "/tmp/ibox_logger.txt";

std::mutex Logger::m_mutex;

std::shared_ptr<Logger> Logger::getInstance() {
    std::unique_lock<std::mutex> lock(m_mutex);
    static std::shared_ptr<Logger> m_instance = Logger::create();
    return m_instance;
}

std::shared_ptr<Logger> Logger::create() {
    auto logger = std::shared_ptr<Logger>(new Logger());
    logger->m_isInitialized = false;
    return logger;
}

int Logger::initialize(Json jNode) {
    std::string rotateLogFileName(ROTATE_LOG_FULL_NAME);
    std::string logPattern("[%Y-%m-%d %H:%M:%S.%e]<%L>%v");
    uint32_t logFileMaxSize = MAX_LOG_FILE_SIZE * 1024 * 1024;
    uint32_t logFileMaxNum = MAX_LOG_FILE_NUM;
    bool logOnConsole = true;
    LoggerLevel logLevel = Logger::LOGGER_DEFAULT_LEVEL;

    if (m_isInitialized) {
        return 0;
    }

    if (jNode.count("logger") > 0) {
        auto loggerNode = jNode["logger"];
        rotateLogFileName = loggerNode["logFileFullName"];
        logFileMaxSize = static_cast<uint32_t>(loggerNode["logFileMaxSize"]) * 1024 * 1024;
        logFileMaxNum = loggerNode["logFilesCount"];
        logPattern = loggerNode["logPattern"];
        logOnConsole = ((int)loggerNode["logOnConsole"] > 0) ? true : false;
        logLevel = getLevelFromString(loggerNode["logLevel"]);
    }

    std::cout << "rotateLogFileName:" << rotateLogFileName << std::endl;
    std::cout << "logFileMaxSize:" << logFileMaxSize << std::endl;
    std::cout << "logFileMaxNum:" << logFileMaxNum << std::endl;
    std::cout << "logPattern:" << logPattern << std::endl;
    std::cout << "logOnConsole:" << logOnConsole << std::endl;
    std::cout << "logLevel:" << static_cast<int>(logLevel) << std::endl;

    spdlog::set_level(spdlog::level::trace);
    m_level = logLevel;
    spdlog::set_pattern(logPattern);

    m_spdRotateFileLogger =
        spdlog::rotating_logger_mt<spdlog::async_factory>(ROTATE_LOGGER_NAME, rotateLogFileName, logFileMaxSize, logFileMaxNum);
    m_spdConsoleLogger = spdlog::stdout_logger_mt<spdlog::async_factory>(CONSOLE_LOGGER_NAME);
    if (m_spdRotateFileLogger && m_spdConsoleLogger) {
        m_consoleLoggerOnFlag = logOnConsole;
        m_isInitialized = true;
        return 0;
    }

    return -1;
}

void Logger::setLevel(LoggerLevel level) {
    m_level = level;
}

bool Logger::shouldLog(LoggerLevel level) {
    return level >= m_level;
}

void Logger::setConsoleLoggerFlag(bool onFlag) {
    m_consoleLoggerOnFlag = onFlag;
}

bool Logger::isConsoleLoggerOn() {
    return m_consoleLoggerOnFlag;
}

Logger::LoggerLevel getLevelFromString(const std::string& level) {
    if (level == "TRACE") {
        return Logger::LoggerLevel::TRACE;
    } else if (level == "DEBUG") {
        return Logger::LoggerLevel::DBG;
    } else if (level == "INFO") {
        return Logger::LoggerLevel::INFO;
    } else if (level == "WARNING") {
        return Logger::LoggerLevel::WARN;
    } else if (level == "ERROR") {
        return Logger::LoggerLevel::ERR;
    } else if (level == "CRITICAL") {
        return Logger::LoggerLevel::CRITICAL;
    } else {
        return Logger::LoggerLevel::OFF;
    }
}

}  // namespace my_toolskit
