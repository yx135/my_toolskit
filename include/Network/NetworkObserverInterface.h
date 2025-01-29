#pragma once

namespace intellBoxSDK {

class NetworkObserverInterface {
public:
    enum NetworkStatus {
        IDLE,
        DISCONNECT,
        CONNECT,
    };

    virtual ~NetworkObserverInterface() = default;

    virtual void onNetworkChanged(
        const std::string& ifName,
        const std::string& ip,
        const std::string& mask,
        const std::string& gw) = 0;
    virtual void onNetworkStatusChanged(const std::string& ifName, NetworkStatus status) = 0;
};

}  // namespace intellBoxSDK
