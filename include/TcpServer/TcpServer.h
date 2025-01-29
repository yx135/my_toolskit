#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <unordered_map>

#include "ev.h"
#include "ev++.h"

#include "IntellBoxCommon/Utils/TcpServer/TcpServerInterface.h"

namespace intellBoxSDK {

class TcpServer : public TcpServerInterface {
public:
    ~TcpServer() = default;

    /**
     * @brief create a TcpServer object
     * 
     * @param serverIP listened ip
     * @param portNum  listened portNum
     * @return std::shared_ptr<TcpServerInterface>
     */
    static std::shared_ptr<TcpServerInterface> create(const std::string& serverIP, uint16_t portNum);

    /// @name TcpServerInterface Functions
    /// @{
    bool isClientConnected(const std::string& clientIP) override;
    int start() override;
    int sendData(const std::string& clientIP, const uint8_t* buffer, uint32_t bufferSize) override;
    void disconnectClient(const std::string& clientIP) override;
    void addTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) override;
    void removeTcpServerObserver(std::shared_ptr<TcpServerObserverInterface> ob) override;
    /// @}

private:
    TcpServer() = default;
    /**
     * @brief when a client connected, the accept call back will be triggered
     * 
     * @param watcher the libev watcher
     * @param revents the libev revents
     */
    void acceptCallback(ev::io& watcher, int revents);
    void readCallback(ev::io& watcher, int revents);

    /**
     * @brief intialize the 
     * 
     * @param serverIP 
     * @param portNum 
     * @return int 0 success, other failure
     */
    int initialize(const std::string& serverIP, uint16_t portNum);

    /**
     * @brief Get the Client Watcher object by clientIP
     * 
     * @param clientIP 
     * @return std::shared_ptr<ev::io> 
     */
    std::shared_ptr<ev::io> getClientWatcher(const std::string& clientIP);

    /**
     * @brief Get the Client IP object by fd
     * 
     * @param fd 
     * @return std::string 
     */
    std::string getClientIP(int fd);
    void addClient(const std::string& ipAddr, std::shared_ptr<ev::io> watcher);
    void removeClient(const std::string& ipAddr);

    void notifyClientDataRecv(const std::string& clientIP, uint8_t* buffer, uint32_t bufferSize);
    void notifyClientConnected(const std::string& clientIP);
    void notifyClientDisconnected(const std::string& clientIP);

    std::thread m_loopThread;


    int m_sockFd;
    mutable std::mutex m_tcpServerObserversMutex;
    mutable std::mutex m_clientsMutex;
    std::unordered_set<std::shared_ptr<TcpServerObserverInterface>> m_tcpServerObservers;
    std::unordered_map<std::string, std::shared_ptr<ev::io>> m_clients;
};

}  // namespace intellBoxSDK
