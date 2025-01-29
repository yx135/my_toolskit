#pragma once

#include <string>
#include <memory>

namespace intellBoxSDK {

class TcpServerObserverInterface {
public:
    virtual ~TcpServerObserverInterface() = default;

    /**
     * @brief Notify the connected event when client connect
     * 
     * @param ipAddress 
     */
    virtual void onClientConnected(const std::string& ipAddress) = 0;

    /**
     * @brief notify the disconnected event when client disconnect
     * 
     * @param ipAddress 
     */
    virtual void onClientDisconnected(const std::string& ipAddress) = 0;

    /**
     * @brief notify the data when data received
     * 
     * @param ipAddress 
     * @param buf 
     * @param len 
     */
    virtual void onClientDataRecv(const std::string& ipAddress, uint8_t* buf, uint32_t len) = 0;

};

}  // namespace intellBoxSDK
