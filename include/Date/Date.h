#pragma once

#include <string>
#include <memory>

namespace intellBoxSDK {

class Date {
public:
    ~Date();
    static std::shared_ptr<Date> create();
    int setTime(const std::string& lT);
    int setTime(time_t lT);
    int getTime(std::string& gettimeval);

private:
    const std::string m_setTimezone = "Asia/Shanghai";
    const std::string m_setSymFile = "/etc/localtime";
    const std::string m_timezonePath = "/usr/share/zoneinfo/";

    Date();

    int initialize();
    int setTimeCommon(struct timeval& tv);
    int setTimezone(const std::string& timez);
};

}  // namespace intellBoxSDK
