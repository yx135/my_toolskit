#include <iostream>
#include <unistd.h>
#include <time.h>
#include <cstring>
#include <sys/time.h>
#include <linux/rtc.h>

#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/Date/Date.h"

namespace intellBoxSDK {

#define BUF_SIZE 200

Date::Date() {
}

Date::~Date() {
}

int Date::initialize() {
    if (0 != setTimezone(m_setTimezone.c_str())) {
        return -1;
    }

    return 0;
}

std::shared_ptr<Date> Date::create() {
    auto dateInfo = std::shared_ptr<Date>(new Date());
    if (dateInfo) {
        if (0 == dateInfo->initialize()) {
            return dateInfo;
        }
    }

    return nullptr;
}

int Date::setTimezone(const std::string& timez) {
    std::string tzPath(m_timezonePath + timez);
    if (0 != access(tzPath.c_str(), R_OK)) {
        LOG_ERROR("[Date:{0}]access tzPath:{1} failed", __LINE__, tzPath);
        return -1;
    }

    if (0 != remove(m_setSymFile.c_str())) {
        LOG_ERROR("[Date:{0}]remove m_setSymFile:{1} failed", __LINE__, m_setSymFile);
        return -1;
    }

    if (0 != symlink(tzPath.c_str(), m_setSymFile.c_str())) {
        LOG_ERROR("[Date:{0}]symlink failed", __LINE__);
        return -1;
    }

    return 0;
}

int Date::setTime(const std::string& lT) {
    struct tm _tm;
    struct rtc_time tm;
    struct timeval tv;
    time_t mkTime;
    memset(&tm, '\0', sizeof(struct rtc_time));
    memset(&_tm, '\0', sizeof(struct tm));

    sscanf(lT.c_str(), "%d-%d-%d %d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    _tm.tm_sec = tm.tm_sec;
    _tm.tm_min = tm.tm_min;
    _tm.tm_hour = tm.tm_hour;
    _tm.tm_mday = tm.tm_mday;
    _tm.tm_mon = tm.tm_mon - 1;
    _tm.tm_year = tm.tm_year - 1900;

    mkTime = mktime(&_tm);

    tv.tv_sec = mkTime;
    tv.tv_usec = 0;

    return setTimeCommon(tv);
}

int Date::setTimeCommon(struct timeval& tv) {
    if (0 != settimeofday(&tv, nullptr)) {
        std::cout << "Error: Set localtime failed. error number is " << errno << "." << std::endl;
        return -1;
    }

    if (0 != system("hwclock -w")) {
        return -1;
    }

    return 0;
}

int Date::setTime(time_t lT) {
    struct timeval tv;
    tv.tv_sec = lT;
    tv.tv_usec = 0;

    return setTimeCommon(tv);
}

int Date::getTime(std::string& gettimeval) {
    time_t t;
    struct tm* loc;
    char buf[BUF_SIZE] = {0};

    if (nullptr == setlocale(LC_ALL, "")) {
        return -1;
    }

    t = time(nullptr);
    loc = localtime(&t);
    if (loc == nullptr) {
        return -1;
    }

    if (0 == strftime(buf, BUF_SIZE, "%Y-%m-%d, %A, %H:%M:%S %Z", loc)) {
        return -1;
    }

    gettimeval = buf;
    return 0;
}

}  // namespace intellBoxSDK
