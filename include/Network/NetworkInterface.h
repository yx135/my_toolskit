#pragma once

#include <stdint.h>
#include <memory>
#include <string>
#include "IntellBoxCommon/SDKInterfaces/Error.h"
#include "IntellBoxCommon/Utils/Network/NetworkObserverInterface.h"
namespace intellBoxSDK {

class NetworkInterface {
public:
    virtual ~NetworkInterface() = default;

    virtual Error getNetwork(const std::string& ifName, std::string& ip, std::string& mask, std::string& gw) = 0;
    virtual Error setNetwork(
        const std::string& ifName,
        const std::string& ip,
        const std::string& mask,
        const std::string& gw) = 0;
    virtual Error setMac(const std::string& ifName, const std::string& macAddress) = 0;
    virtual std::string getMac(const std::string& ifName) = 0;
    virtual Error setGateway(
        const std::string& ifName,
        const std::string& gw,
        const std::string& ip,
        const std::string& mask,
        bool host) = 0;

    virtual void addNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob) = 0;
    virtual void removeNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob) = 0;
};

}  // namespace intellBoxSDK
