#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <string>
#include "IntellBoxCommon/Utils/Network/NetworkObserverInterface.h"
#include "IntellBoxCommon/Utils/Network/NetworkManager.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"

namespace intellBoxSDK {

#define NET_ENTRY_ROUTE "/proc/net/route"
#define ROUTE_INFO_SIZE 128

#define JSON_CONF "/etc/network.json"
#define HOST_MASK "255.255.255.255"

struct route_info {
    char name[IFNAMSIZ];
    struct in_addr dst_addr;
    struct in_addr rt_addr;
    short flags;
    short ref_cnt;
    short use;
    short metric;
    struct in_addr mask_addr;
    int mtu;
    int window;
    int IRTT;
    struct route_info *prev, *next;
};

NetworkManager::NetworkManager() {
    m_sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_sfd < 0) {
        LOG_ERROR("[{0}][{1}] Create socket failed.", __FUNCTION__, __LINE__);
    }
}

std::shared_ptr<NetworkManager> NetworkManager::create(const std::string& networkConf) {
    auto networkManager = std::shared_ptr<NetworkManager>(new NetworkManager());
    if (networkManager) {
        if (Error::SUCCESS == networkManager->initNetwork(networkConf)) {
            return networkManager;
        }
    }

    return nullptr;
}

Error NetworkManager::convertMactoSockAddr(const std::string& addr, struct sockaddr& sockAddr) {
    int i = 0, j = 0, k;
    std::string mac_data;
    long int data;
    while (1) {
        if (addr[i] == ':' || addr[i] == '\0') {
            if (mac_data.length() > 2) {
                LOG_ERROR("[{0}][{1}] MAC data length wrong.", __FUNCTION__, __LINE__);
                return Error::GENERAL_FAIL;
            }

            for (k = 0; k < 2; k++) {
                if ((mac_data[k] < 0x47 && mac_data[k] > 0x40) || (mac_data[k] < 0x3A && mac_data[k] > 0x2F) ||
                    (mac_data[k] < 0x67 && mac_data[k] > 0x60) || mac_data[k] == '\0')
                    continue;
                else {
                    LOG_ERROR("[{0}][{1}] Please Input correctly mac address.", __FUNCTION__, __LINE__);
                    return Error::GENERAL_FAIL;
                }
            }
            data = strtol(mac_data.c_str(), NULL, 16);
            sockAddr.sa_data[j++] = data & 0377;

            mac_data.clear();
            if (addr[i] == '\0') {
                break;
            }
        } else {
            mac_data += addr[i];
        }
        i++;
    }
    return Error::SUCCESS;
}

Error NetworkManager::setInet(const std::string& name, const std::string& addr, networkFlag flag) {
    struct ifreq ifr;
    struct in_addr i_addr;
    struct sockaddr_in sin;

    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (flag == networkFlag::SET_MAC) {
        if (Error::SUCCESS != convertMactoSockAddr(addr, ifr.ifr_hwaddr)) {
            LOG_ERROR("[{0}][{1}] Convert mac to sock address failed.", __FUNCTION__, __LINE__);
            return Error::GENERAL_FAIL;
        }
    } else if (!inet_aton(addr.c_str(), &i_addr)) {
        LOG_ERROR("[{0}][{1}] Please input correct addr.", __FUNCTION__, __LINE__);
        return Error::GENERAL_FAIL;
    } else {
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, &i_addr, sizeof(struct in_addr));
        memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
    }

    unsigned long ifreq = -1;
    switch (flag) {
        case networkFlag::SET_IP: {
            ifreq = SIOCSIFADDR;
            break;
        }
        case networkFlag::SET_NETMASK: {
            ifreq = SIOCSIFNETMASK;
            break;
        }
        case networkFlag::SET_MAC: {
            ifreq = SIOCSIFHWADDR;
            break;
        }
        default:
            break;
    }
    if (ioctl(m_sfd, ifreq, &ifr) < 0) {
        LOG_ERROR("[{0}][{1}]: ioctl {2} failed.", __FUNCTION__, __LINE__, static_cast<char>(flag));
        return Error::GENERAL_FAIL;
    }

    return Error::SUCCESS;
}

void NetworkManager::onNotifyInterface(
    const std::string& ifName,
    const std::string& ip,
    const std::string& mask,
    const std::string& gw) {
    for (auto ob : m_observers) {
        ob->onNetworkChanged(ifName, ip, mask, gw);
    }
}

Error NetworkManager::setGateway(
    const std::string& ifName,
    const std::string& gw,
    const std::string& ip,
    const std::string& mask,
    bool host) {
    std::string defaultGW;
    struct rtentry rt;
    struct sockaddr_in sip, smask, sgw;

    memset((char*)&rt, '\0', sizeof(struct rtentry));
    memset((char*)&sip, '\0', sizeof(struct sockaddr_in));
    memset((char*)&smask, '\0', sizeof(struct sockaddr_in));
    memset((char*)&sgw, '\0', sizeof(struct sockaddr_in));

    if (ifName.empty()) {
        LOG_ERROR("[{0}][{1}] Please input ifName.", __FUNCTION__, __LINE__);
        return Error::GENERAL_FAIL;
    }

    if (gw.empty()) {
        auto netcardInfo = m_netcardInfo["networks"];
        for (auto netcardNode : netcardInfo) {
            if (netcardNode["interface"] == ifName && netcardNode.count("gateway")) {
                defaultGW = netcardNode["gateway"];
                break;
            }
        }
        if (defaultGW.empty()) {
            LOG_ERROR("[{0}][{1}] Please configure [{2}] valid gateway.", __FUNCTION__, __LINE__, ifName);
            return Error::GENERAL_FAIL;
        }
    }

    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    rt.rt_metric = 100;
    rt.rt_dev = (char*)ifName.c_str();

    sip.sin_family = AF_INET;
    if (!ip.empty()) {
        sip.sin_addr.s_addr = inet_addr(ip.c_str());
    }
    memcpy(&rt.rt_dst, (struct sockaddr*)&sip, sizeof(sip));

    smask.sin_family = sip.sin_family;
    if (!mask.empty()) {
        smask.sin_addr.s_addr = inet_addr(mask.c_str());
    }

    if (host) {
        rt.rt_flags |= RTF_HOST;
        smask.sin_addr.s_addr = inet_addr(HOST_MASK);
    }
    memcpy(&rt.rt_genmask, (struct sockaddr*)&smask, sizeof(smask));

    sgw.sin_family = sip.sin_family;
    if (defaultGW.empty()) defaultGW = gw;
    if (!inet_aton(defaultGW.c_str(), &sgw.sin_addr)) {
        LOG_ERROR("[{0}][{1}] Param [{2}] wrong.", __FUNCTION__, __LINE__, defaultGW);
        return Error::GENERAL_FAIL;
    }
    memcpy(&rt.rt_gateway, (struct sockaddr*)&sgw, sizeof(sgw));

    if (ioctl(m_sfd, SIOCADDRT, &rt) < 0) {
        clearAllRoute(rt);
        if (ioctl(m_sfd, SIOCADDRT, &rt) < 0) {
            LOG_ERROR("[{0}][{1}] Gateway set failed.", __FUNCTION__, __LINE__);
            return Error::GENERAL_FAIL;
        }
    }

    return Error::SUCCESS;
}

Error NetworkManager::initNetwork(const std::string& networkConf) {
    Error retVal = Error::SUCCESS;
    if (networkConf.length()) {
        m_confFile = networkConf;
    } else {
        m_confFile = JSON_CONF;
    }

    std::ifstream configFileStream(m_confFile);
    if (!configFileStream.is_open()) {
        LOG_ERROR("[{0}][{1}] Configure file has open.", __FUNCTION__, __LINE__);
        return Error::SUCCESS;
    }

    configFileStream >> m_netcardInfo;

    auto netInfo = m_netcardInfo.count("networks") == 0 ? "" : m_netcardInfo["networks"];
    for (auto netcardInfo : netInfo) {
        if (netcardInfo.count("interface") > 0) {
            if (netcardInfo.count("ip") == 0) {
                continue;
            }
            std::string ip = netcardInfo["ip"],
                        netmask = netcardInfo.count("netmask") == 0 ? "" : netcardInfo["netmask"],
                        gateway = netcardInfo.count("gateway") == 0 ? "" : netcardInfo["gateway"];
            retVal = setNetwork(netcardInfo["interface"], ip, netmask, gateway);
            if (Error::SUCCESS != retVal) {
                return retVal;
            }
        }
    }

    if (m_netcardInfo.count("defaultInterface") > 0) {
        retVal = setGateway(m_netcardInfo["defaultInterface"]);
        if (Error::SUCCESS != retVal) {
            LOG_ERROR(
                "[{0}][{1}] Not found {2} from NetworksConf.json",
                __FUNCTION__,
                __LINE__,
                m_netcardInfo["defaultInterface"]);
            return retVal;
        }
    }
    configFileStream.close();

    return Error::SUCCESS;
}

void NetworkManager::syncNetworkConfigure(
    const std::string& netcard,
    const std::string& ip,
    const std::string& mask,
    const std::string& gw) {
    auto& netInfo = m_netcardInfo["networks"];

    int findFlag = -1;
    for (auto& cardInfo : netInfo) {
        if (0 == netcard.compare(cardInfo["interface"])) {
            cardInfo["ip"] = ip;
            if (!mask.empty()) cardInfo["netmask"] = mask;
            if (!gw.empty()) cardInfo["gateway"] = gw;
            findFlag = 0;
            break;
        }
    }
    Json item, array = Json::array();
    item["interface"] = netcard;
    item["ip"] = ip;
    if (!mask.empty()) item["netmask"] = mask;
    if (!gw.empty()) item["gateway"] = gw;

    if (netInfo.empty()) {
        array.push_back(item);
        m_netcardInfo["networks"] = array;
    } else if (0 != findFlag) {
        netInfo.push_back(item);
    }

    std::ofstream out(m_confFile);
    out << m_netcardInfo.dump(2);
    out.close();
}

Error NetworkManager::getNetwork(const std::string& ifName, std::string& ip, std::string& mask, std::string& gw) {
    ip = getInet(ifName, networkFlag::GET_IP);
    mask = getInet(ifName, networkFlag::GET_NETMASK);
    gw = getGateWay(ifName);

    // All strings arm non-empty
    if (ip.length() && mask.length() && gw.length()) {
        return Error::SUCCESS;
    }
    return Error::GENERAL_FAIL;
}

Error NetworkManager::setNetwork(
    const std::string& ifName,
    const std::string& ip,
    const std::string& mask,
    const std::string& gw) {
    Error retVal = Error::SUCCESS;
    // All strings arm non-empty
    if (ifName.length() && ip.length()) {
        retVal = setInet(ifName, ip, networkFlag::SET_IP);
        if (retVal != Error::SUCCESS) {
            LOG_ERROR("[{0}][{1}] Set ip failed.", __FUNCTION__, __LINE__);
            return Error::GENERAL_FAIL;
        }

        if (mask.length()) {
            retVal = setInet(ifName, mask, networkFlag::SET_NETMASK);
            if (retVal != Error::SUCCESS) {
                LOG_ERROR("[{0}][{1}] Set netmask failed.", __FUNCTION__, __LINE__);
                return Error::GENERAL_FAIL;
            }
        }

        if (gw.length()) {
            retVal = setGateway(ifName, gw);
            if (retVal != Error::SUCCESS) {
                LOG_ERROR("[{0}][{1}] Set gateway failed.ifName:{2}, gw:{3}", __FUNCTION__, __LINE__, ifName, gw);
                return Error::GENERAL_FAIL;
            }
        }

        syncNetworkConfigure(ifName, ip, mask, gw);

        onNotifyInterface(ifName, ip, mask, gw);

        return Error::SUCCESS;
    }
    return Error::INVALID_PARA;
}

void NetworkManager::clearAllRoute(struct rtentry rt) {
    std::string getInfo;
    struct sockaddr_in sin;
    char buf[ROUTE_INFO_SIZE] = {0};
    unsigned char read_len = ROUTE_INFO_SIZE - 1;
    struct route_info rt_info = {0};

    if (access(NET_ENTRY_ROUTE, F_OK)) {
        // LOG_ERROR("{0} file dosen't exist.", NET_ENTRY_ROUTE);
        return;
    }

    FILE* fp = fopen(NET_ENTRY_ROUTE, "r");
    if (!fp) {
        // LOG_ERROR("Open {0} failed.", NET_ENTRY_ROUTE);
        return;
    }

    while (read_len == fread(buf, sizeof(buf[0]), read_len, fp)) {
        if (!strlen(buf)) {
            continue;
        }
        buf[read_len] = '\0';

        sscanf(
            buf,
            "%s %x %x %u %u %u %u %x %d %d %d",
            rt_info.name,
            &rt_info.dst_addr.s_addr,
            &rt_info.rt_addr.s_addr,
            reinterpret_cast<unsigned int*>(&rt_info.flags),
            reinterpret_cast<unsigned int*>(&rt_info.ref_cnt),
            reinterpret_cast<unsigned int*>(&rt_info.use),
            reinterpret_cast<unsigned int*>(&rt_info.metric),
            &rt_info.mask_addr.s_addr,
            &rt_info.mtu,
            &rt_info.window,
            &rt_info.IRTT);

        if (!rt_info.rt_addr.s_addr) {
            continue;
        }

        if (!strncmp(rt_info.name, rt.rt_dev, strlen(rt.rt_dev))) {
            memset((char*)&sin, '\0', sizeof(struct sockaddr_in));
            rt.rt_metric = rt_info.metric + (rt_info.metric != 0 ? 1 : 0);
            sin.sin_addr = rt_info.rt_addr;
            memcpy(&rt.rt_gateway, (struct sockaddr*)&sin, sizeof(struct sockaddr));
            LOG_INFO("[{0}][{1}] SIN.SIN_ADDR:{2}", __FUNCTION__, __LINE__, inet_ntoa(sin.sin_addr));
            ioctl(m_sfd, SIOCDELRT, &rt);
        }
    }

    fclose(fp);
}

Error NetworkManager::setMac(const std::string& ifName, const std::string& macAddress) {
    m_mac = macAddress;
    if (!strcmp(m_mac.c_str(), getMac(ifName).c_str())) {
        LOG_ERROR("[{0}][{1}] Set Mac is same as now.", __FUNCTION__, __LINE__);
        return Error::SUCCESS;
    }
    return setInet(ifName, macAddress, networkFlag::SET_MAC);
}

std::string NetworkManager::getInet(const std::string& ifName, networkFlag flag) {
    std::string getInfo;
    struct ifreq ifr;
    unsigned long ifreqFlag = -1;

    memset(&ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifName.c_str(), ifName.length());
    ifr.ifr_addr.sa_family = AF_INET;

    switch (flag) {
        case networkFlag::GET_IP: {
            ifreqFlag = SIOCGIFADDR;
            break;
        }
        case networkFlag::GET_NETMASK: {
            ifreqFlag = SIOCGIFNETMASK;
            break;
        }
        case networkFlag::GET_MAC: {
            ifreqFlag = SIOCGIFHWADDR;
            break;
        }
        default:
            return "";
    }
    if (ioctl(m_sfd, ifreqFlag, &ifr) < 0) {
        LOG_ERROR("[{0}][{1}]: ioctl failed.", __FUNCTION__, __LINE__);
        return "";
    }

    char cp_data[IFNAMSIZ + 2] = {0};
    if (flag == networkFlag::GET_MAC) {
        char mac_data[9] = {0};
        memcpy(mac_data, ifr.ifr_hwaddr.sa_data, 8);
        snprintf(
            cp_data,
            IFNAMSIZ + 2,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            (mac_data[0] & 0377),
            (mac_data[1] & 0377),
            (mac_data[2] & 0377),
            (mac_data[3] & 0377),
            (mac_data[4] & 0377),
            (mac_data[5] & 0377));
    } else if (flag == networkFlag::GET_NETMASK) {
        sprintf(cp_data, "%s", inet_ntoa((reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask))->sin_addr));
    } else {
        sprintf(cp_data, "%s", inet_ntoa((reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr))->sin_addr));
    }

    return getInfo = cp_data;
}

std::string NetworkManager::getGateWay(const std::string& ifName) {
    std::string getInfo;
    char buf[ROUTE_INFO_SIZE] = {0};
    unsigned char read_len = ROUTE_INFO_SIZE - 1;
    struct route_info rt_info = {0};

    if (access(NET_ENTRY_ROUTE, F_OK)) {
        LOG_ERROR("[{0}][{1}] {2} file dosen't exist.", __FUNCTION__, __LINE__, NET_ENTRY_ROUTE);
        return "";
    }

    FILE* fp = fopen(NET_ENTRY_ROUTE, "r");
    if (!fp) {
        LOG_ERROR("[{0}][{1}] Open {2} failed.", __FUNCTION__, __LINE__, NET_ENTRY_ROUTE);
        return "";
    }

    while (read_len == fread(buf, sizeof(buf[0]), read_len, fp)) {
        if (!strlen(buf)) {
            continue;
        }
        buf[read_len] = '\0';

        sscanf(
            buf,
            "%s %x %x %u %u %u %u %x %d %d %d",
            rt_info.name,
            &rt_info.dst_addr.s_addr,
            &rt_info.rt_addr.s_addr,
            reinterpret_cast<unsigned int*>(&rt_info.flags),
            reinterpret_cast<unsigned int*>(&rt_info.ref_cnt),
            reinterpret_cast<unsigned int*>(&rt_info.use),
            reinterpret_cast<unsigned int*>(&rt_info.metric),
            &rt_info.mask_addr.s_addr,
            &rt_info.mtu,
            &rt_info.window,
            &rt_info.IRTT);

        if (!rt_info.rt_addr.s_addr) {
            continue;
        }

        if (!strncmp(rt_info.name, ifName.c_str(), ifName.length())) {
            char cp_data[IFNAMSIZ] = {0};
            sprintf(cp_data, "%s", inet_ntoa(rt_info.rt_addr));
            fclose(fp);
            return getInfo = cp_data;
        }
    }

    fclose(fp);
    return "";
}

std::string NetworkManager::getMac(const std::string& ifName) {
    return getInet(ifName, networkFlag::GET_MAC);
}

void NetworkManager::addNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock{m_mutex};
        m_observers.insert(ob);
    }
}

void NetworkManager::removeNetworkObserver(std::shared_ptr<NetworkObserverInterface> ob) {
    std::unique_lock<std::mutex> lock{m_mutex};
    m_observers.erase(ob);
}

NetworkManager::~NetworkManager() {
    close(m_sfd);
}

}  // namespace intellBoxSDK
