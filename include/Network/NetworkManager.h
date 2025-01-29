#pragma once

#include <string>
#include <mutex>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unordered_set>
#include "IntellBoxCommon/Utils/Network/NetworkInterface.h"
#include "nlohmann/json.hpp"

namespace intellBoxSDK {

using Json = nlohmann::json;

class NetworkManager : public NetworkInterface {
public:
    static std::shared_ptr<NetworkManager> create(const std::string& networkConf);

    Error getNetwork(const std::string& ifName, std::string& ip, std::string& mask, std::string& gw);
    Error setNetwork(const std::string& ifName, const std::string& ip, const std::string& mask, const std::string& gw);

    Error setMac(const std::string& ifName, const std::string& macAddress);
    std::string getMac(const std::string& ifName);
    Error setGateway(
        const std::string& ifName,
        const std::string& gw = "",
        const std::string& ip = "",
        const std::string& mask = "",
        bool host = false);

    void addNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob);
    void removeNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob);
    ~NetworkManager();

private:
    enum class networkFlag {
        GET_IP,
        GET_NETMASK,
        GET_MAC,
        SET_IP,
        SET_NETMASK,
        SET_MAC,
    };

    std::unordered_set<std::shared_ptr<NetworkObserverInterface>> m_observers;
    std::mutex m_mutex;
    std::string m_mac;

    std::string m_confFile;
    Json m_netcardInfo;
    int m_sfd;

    NetworkManager();

    Error initNetwork(const std::string& networkConf);
    void syncNetworkConfigure(
        const std::string& netcard,
        const std::string& ip,
        const std::string& mask,
        const std::string& gw);

    Error convertMactoSockAddr(const std::string& addr, struct sockaddr& sockAddr);
    std::string getInet(const std::string& ifName, networkFlag flag);
    Error setInet(const std::string& name, const std::string& addr, networkFlag flag);
    std::string getGateWay(const std::string& ifName);
    void onNotifyInterface(
        const std::string& ifName,
        const std::string& ip,
        const std::string& mask,
        const std::string& gw);
    void clearAllRoute(struct rtentry rt);
};

}  // namespace intellBoxSDK
