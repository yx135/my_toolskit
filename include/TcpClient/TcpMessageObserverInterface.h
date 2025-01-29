#pragma once
#include "TcpMessageStruct.h"
#include <string>
namespace intellBoxSDK {

class TcpMessageObserverInterface {
public:
    virtual ~TcpMessageObserverInterface() = default;
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
     * @brief notify observer when controller message received
     *
     * @param tcpMessage TcpMessage
     */
    virtual void onTcpMessageRecv(const TcpMessage* tcpMessage) = 0;
};

}  // namespace intellBoxSDK
