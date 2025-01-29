#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <condition_variable>

#include "ev.h"
#include "ev++.h"

#include "IntellBoxCommon/Utils/TcpClient/TcpClientInterface.h"
#include "IntellBoxCommon/Utils/Timer/Timer.h"
#include "IntellBoxCommon/Utils/Threading/Executor.h"
namespace intellBoxSDK {

class TcpClient : public TcpClientInterface {
public:
    ~TcpClient();

    /**
     * @brief create a TcpClient object
     *
     * @param serverIp connected ip
     * @param serverPort  connected serverPort
     * @return std::shared_ptr<TcpClient>
     */
    static std::shared_ptr<TcpClient> create(const std::string& serverIp, uint16_t serverPort, int connectInterval);

    /// @name TcpClientInterface Functions
    /// @{
    bool isConnected() override;
    int sendData(const void* buffer, uint32_t bufferSize, const std::chrono::seconds& timeout) override;
    void setServer(const std::string& serverIp, uint16_t serverPort) override;
    void getServer(std::string& serverIp, uint16_t& serverPort) override;
    void disconnect() override;
    void addTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) override;
    void removeTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) override;
    /// @}

private:
    TcpClient(const std::string& serverIP, uint16_t serverPort, int connectInterval);

    void readCallback(ev::io& watcher, int revents);

    /**
     * @brief intialize the
     *
     * @return int 0 success, other failure
     */
    int initialize();

    void connectThread();
    int checkConnect();

    void notifyDataRecv(uint8_t* buffer, uint32_t bufferSize);
    void notifyConnected(const std::string& serverIp, uint16_t serverPort);
    void notifyDisconnected(const std::string& serverIp, uint16_t serverPort);
    void slotTimerOut();

    bool m_quitFlag;
    std::thread m_connectThread;
    std::thread m_loopThread;
    std::condition_variable m_connectCV;

    ev::io m_readIO;
    ev::dynamic_loop* m_evLoop;

    int m_sockFd;
    bool m_isConncted;
    uint16_t m_serverPort;
    std::string m_serverIp;
    int m_connectInterval;

    mutable std::mutex m_tcpClientObserversMutex;
    std::unordered_set<std::shared_ptr<TcpClientObserverInterface>> m_tcpClientObservers;
    std::shared_ptr<Timer> m_timer;
    Executor m_executor;
    std::atomic_bool m_isTimerOut;
};

}  // namespace intellBoxSDK
