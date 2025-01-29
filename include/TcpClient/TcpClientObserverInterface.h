#pragma once

#include <string>
#include <memory>

namespace intellBoxSDK {

class TcpClientObserverInterface {
public:
    virtual ~TcpClientObserverInterface() = default;

    /**
     * @brief Notify the connected event when connect
     *
     * @param serverIp
     * @param serverPort
     */
    virtual void onConnected(const std::string& serverIp, uint16_t serverPort) = 0;

    /**
     * @brief Notify the disconnected event when disconnect
     *
     * @param serverIp
     * @param serverPort
     */
    virtual void onDisconnected(const std::string& serverIp, uint16_t serverPort) = 0;

    /**
     * @brief Notify the data when data received
     *
     * @param ipAddress
     * @param buf
     * @param len
     */
    virtual void onDataRecv(uint8_t* buf, uint32_t len) = 0;
};

}  // namespace intellBoxSDK
