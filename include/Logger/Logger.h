#pragma once

#include <memory>
#include <nlohmann/json.hpp>
#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

using Json = nlohmann::json;

namespace my_toolskit {

class Logger {
public:
    enum class LoggerLevel {
        TRACE = 0,
        DBG = 1,
        INFO = 2,
        WARN = 3,
        ERR = 4,
        CRITICAL = 5,
        OFF = 6,
    };

    ~Logger() = default;

    static std::shared_ptr<Logger> getInstance();

    int initialize(Json jNode);

    void setLevel(LoggerLevel level);
    void setConsoleLoggerFlag(bool onFlag);

    template <typename... Args>
    void trace(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::TRACE)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->trace(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->trace(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

    template <typename... Args>
    void info(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::INFO)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->info(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->info(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

    template <typename... Args>
    void debug(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::DBG)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->debug(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->debug(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

    template <typename... Args>
    void warn(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::WARN)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->warn(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->warn(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

    template <typename... Args>
    void error(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::ERR)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->error(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->error(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

    template <typename... Args>
    void critical(const char* fmt, const Args&... args) {
        if (shouldLog(LoggerLevel::CRITICAL)) {
            if (isConsoleLoggerOn()) {
                m_spdConsoleLogger->critical(fmt, args...);
                m_spdConsoleLogger->flush();
            }

            m_spdRotateFileLogger->critical(fmt, args...);
            m_spdRotateFileLogger->flush();
        }
    }

private:
    static const LoggerLevel LOGGER_DEFAULT_LEVEL = LoggerLevel::INFO;

    Logger() = default;
    static std::shared_ptr<Logger> create();
    bool shouldLog(LoggerLevel level);
    bool isConsoleLoggerOn();

    static std::mutex m_mutex;

    LoggerLevel m_level;
    bool m_consoleLoggerOnFlag;
    bool m_isInitialized;
    std::shared_ptr<spdlog::logger> m_spdRotateFileLogger;
    std::shared_ptr<spdlog::logger> m_spdConsoleLogger;
};

}  // namespace intellBoxSDK

#ifdef LOGGER
#define LOG_SETLEVEL(level)                                   \
    do {                                                      \
        intellBoxSDK::Logger::getInstance()->setLevel(level); \
    } while (false)

#define LOG_TRACE(fmt, ...)                                             \
    do {                                                                \
        intellBoxSDK::Logger::getInstance()->trace(fmt, ##__VA_ARGS__); \
    } while (false)

#define LOG_DEBUG(fmt, ...)                                             \
    do {                                                                \
        intellBoxSDK::Logger::getInstance()->debug(fmt, ##__VA_ARGS__); \
    } while (false)

#define LOG_INFO(fmt, ...)                                             \
    do {                                                               \
        intellBoxSDK::Logger::getInstance()->info(fmt, ##__VA_ARGS__); \
    } while (false)

#define LOG_WARN(fmt, ...)                                             \
    do {                                                               \
        intellBoxSDK::Logger::getInstance()->warn(fmt, ##__VA_ARGS__); \
    } while (false)

#define LOG_ERROR(fmt, ...)                                             \
    do {                                                                \
        intellBoxSDK::Logger::getInstance()->error(fmt, ##__VA_ARGS__); \
    } while (false)

#define LOG_CRITICAL(fmt, ...)                                             \
    do {                                                                   \
        intellBoxSDK::Logger::getInstance()->critical(fmt, ##__VA_ARGS__); \
    } while (false)
#else

#define LOG_SETLEVEL(level)
#define LOG_TRACE(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#define LOG_INFO(fmt, ...)
#define LOG_WARN(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_CRITICAL(fmt, ...)

#endif