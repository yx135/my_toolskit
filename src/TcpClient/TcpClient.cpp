#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <poll.h>
#include <unistd.h>

#include <thread>

#include "IntellBoxCommon/SDKInterfaces/Common.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"
#include "IntellBoxCommon/Utils/TcpClient/TcpClient.h"

namespace intellBoxSDK {

TcpClient::~TcpClient() {
    m_quitFlag = true;
    if (-1 != m_sockFd) {
        close(m_sockFd);
        m_sockFd = -1;
    }
    if (m_timer->isActive()) {
        m_timer->stop();
    }
}

std::shared_ptr<TcpClient> TcpClient::create(const std::string& serverIp, uint16_t serverPort, int connectInterval) {
    auto tcpClient = std::shared_ptr<TcpClient>(new TcpClient(serverIp, serverPort, connectInterval));
    if (tcpClient) {
        if (0 == tcpClient->initialize()) {
            return tcpClient;
        }
    }

    return nullptr;
}

bool TcpClient::isConnected() {
    return m_isConncted;
}

int TcpClient::sendData(const void* buffer, uint32_t bufferSize, const std::chrono::seconds& timeout) {
    m_isTimerOut = false;
    if (m_timer->isActive()) {
        m_timer->stop();
    }
    if (!m_timer->isActive()) {
        m_timer->start(timeout, timeout, Timer::PeriodType::RELATIVE, 0, std::bind(&TcpClient::slotTimerOut, this));
    }
    uint32_t sendSize = 0;
    static int tryAgainCount = 0;
    while (sendSize < bufferSize) {
        if (m_isTimerOut) {
            if (m_timer->isActive()) {
                m_timer->stop();
            }
            return -1;
        }
        if (-1 != m_sockFd && m_isConncted) {
            auto ret = send(m_sockFd, (uint8_t*)buffer + sendSize, bufferSize - sendSize, 0);
            if (ret < 0) {
                LOG_INFO("[TcpClient:{0}]send failed:{1}", __LINE__, errno);
                if (EAGAIN == errno || EWOULDBLOCK == errno) {
                    if (++tryAgainCount > 5) {
                        tryAgainCount = 0;
                        disconnect();
                        if (m_timer->isActive()) {
                            m_timer->stop();
                        }
                        return ret;
                    }
                    continue;
                }

                tryAgainCount = 0;
                disconnect();
                if (m_timer->isActive()) {
                    m_timer->stop();
                }
                return ret;
            }
            sendSize += ret;
            tryAgainCount = 0;
        } else {
            if (m_timer->isActive()) {
                m_timer->stop();
            }
            return -1;
        }
    }
    if (m_timer->isActive()) {
        m_timer->stop();
    }
    return sendSize;
}

void TcpClient::setServer(const std::string& serverIp, uint16_t serverPort) {
    if (m_serverIp != serverIp || m_serverPort != serverPort) {
        LOG_INFO("setServer disconnect");
        disconnect();

        m_serverIp = serverIp;
        m_serverPort = serverPort;
    }
}

void TcpClient::getServer(std::string& serverIp, uint16_t& serverPort) {
    serverIp = m_serverIp;
    serverPort = m_serverPort;
}

void TcpClient::disconnect() {
    static std::mutex processMutex;
    LOG_INFO("[TcpClient:{0}]disconnect", __LINE__);
    std::unique_lock<std::mutex> lock(processMutex);

    if (m_evLoop == nullptr || !m_isConncted) {
        LOG_INFO("[{0}][{1}] has disconnect.", __FUNCTION__, __LINE__);
        return;
    }
    m_readIO.stop();
    LOG_INFO("[TcpClient:{0}]break_loop", __LINE__);
    m_evLoop->break_loop(ev::ALL);

    if (m_sockFd) {
        close(m_sockFd);
        m_sockFd = -1;
    }

    m_isConncted = false;
    LOG_INFO("[TcpClient:{0}]notify disconnected", __LINE__);
    notifyDisconnected(m_serverIp, m_serverPort);

    /// notify reconnect
    m_connectCV.notify_all();
}

void TcpClient::addTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_tcpClientObserversMutex);
        m_tcpClientObservers.insert(ob);
    }
}

void TcpClient::removeTcpClientObserver(std::shared_ptr<TcpClientObserverInterface> ob) {
    if (ob) {
        std::unique_lock<std::mutex> lock(m_tcpClientObserversMutex);
        m_tcpClientObservers.erase(ob);
    }
}

TcpClient::TcpClient(const std::string& serverIP, uint16_t serverPort, int connectInterval) {
    m_serverIp = serverIP;
    m_serverPort = serverPort;
    m_isConncted = false;
    m_sockFd = -1;
    m_quitFlag = false;
    m_connectInterval = connectInterval;

    m_evLoop = nullptr;
    m_isTimerOut = false;
    m_timer = std::make_shared<Timer>();
}

void TcpClient::readCallback(ev::io& watcher, int revents) {
    UNUSED_VAR(revents);

    LOG_DEBUG("[TcpClient:{0}] revents:{1}", __LINE__, revents);
    uint8_t readBuf[512] = {0};
    ssize_t readLen = recv(watcher.fd, readBuf, sizeof(readBuf), 0);
    LOG_TRACE("[TcpClient:{0}] get data length:{1}", __LINE__, readLen);
    if (readLen < 0) {
        LOG_INFO("[TcpClient:{0}]recv error, readLen:{1}, errno:{2}", __LINE__, readLen, errno);
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
            return;
        } else {
            watcher.stop();
            LOG_INFO("errno");
            return;
        }
    } else if (0 == readLen) {
        watcher.stop();
        LOG_ERROR("[TcpClient:{0}]readLen==0 disconnect", __LINE__);
        return;
    }

    notifyDataRecv(readBuf, static_cast<uint32_t>(readLen));
}

int TcpClient::initialize() {
    m_connectThread = std::thread(std::bind(&TcpClient::connectThread, this));
    m_connectThread.detach();

    return 0;
}

void TcpClient::connectThread() {
    LOG_INFO("[TcpClient:{0}]m_quitFlag:{1}", __LINE__, m_quitFlag);

    while (!m_quitFlag) {
        LOG_INFO("[TcpClient:{0}]m_isConncted:{1}", __LINE__, m_isConncted);
        /// if connected, wait for the disconnect
        while (!m_quitFlag && m_isConncted) {
            std::mutex tmpMutex;
            std::unique_lock<std::mutex> lock(tmpMutex);

            /// sleep 2 seconds for next check
            m_connectCV.wait_for(lock, std::chrono::seconds(2), [this] { return m_quitFlag || !m_isConncted; });

            LOG_INFO("[TcpClient:{0}]m_quitFlag:{1}, m_isConncted:{2}", __LINE__, m_quitFlag, m_isConncted);
        }

        time_t t1 = time(nullptr);
        while (!m_quitFlag) {
            if (m_sockFd) {
                close(m_sockFd);
                m_sockFd = -1;
            }

            m_sockFd = socket(AF_INET, SOCK_STREAM, 0);
            if (m_sockFd < 0) {
                continue;
            }

            struct sockaddr_in serverAddress;
            bzero(&serverAddress, sizeof(serverAddress));
            serverAddress.sin_family = AF_INET;
            inet_pton(AF_INET, m_serverIp.c_str(), &serverAddress.sin_addr);
            serverAddress.sin_port = htons(m_serverPort);

            /// default sleep 10 seconds for connecting
            std::this_thread::sleep_for(std::chrono::seconds(m_connectInterval));

            auto ret = connect(m_sockFd, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress));
            LOG_DEBUG("[TcpClient:{0}]ret:{1}, errno:{2}, EINPROGRESS:{3}", __LINE__, ret, errno, EINPROGRESS);
            if (ret == 0) {
                m_isConncted = true;
                break;
            } else if (errno == EINPROGRESS) {
                if (0 == checkConnect()) {
                    m_isConncted = true;
                    break;
                }
            }
        }
        time_t t2 = time(nullptr);

        /// 将当前sockfd设置为非阻塞
        int flags = fcntl(m_sockFd, F_GETFL, 0);
        fcntl(m_sockFd, F_SETFL, flags | O_NONBLOCK);

        LOG_INFO(
            "[TcpClient:{0}]connected server in {3}s, m_serverIp:{1}, m_serverPort:{2}",
            __LINE__,
            m_serverIp,
            m_serverPort,
            t2 - t1);
        notifyConnected(m_serverIp, m_serverPort);

        m_evLoop = new ev::dynamic_loop();
        if (m_evLoop) {
            m_readIO.set(*m_evLoop);
            m_readIO.set<TcpClient, &TcpClient::readCallback>(this);
            m_readIO.start(m_sockFd, ev::READ);

            m_evLoop->run(0);

            disconnect();
            /// release ev loop
            delete m_evLoop;
            m_evLoop = nullptr;
        }

        LOG_INFO("[TcpClient:{0}] reconnect server", __LINE__);
    }
}

int TcpClient::checkConnect() {
    fd_set wSet;
    FD_ZERO(&wSet);
    FD_SET(m_sockFd, &wSet);

    struct timeval tval;
    tval.tv_sec = 2;
    tval.tv_usec = 0;
    if (select(m_sockFd + 1, nullptr, &wSet, nullptr, &tval) <= 0) {
        LOG_INFO("[TcpClient:{0}]checkConnect failed", __LINE__);
        return -1;
    }

    LOG_INFO("[TcpClient:{0}]checkConnect success", __LINE__);

    if (FD_ISSET(m_sockFd, &wSet)) {
        int err = -1;
        socklen_t len = sizeof(int);
        if (getsockopt(m_sockFd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
            LOG_ERROR("[TcpClient:{0}]getsockopt failed", __LINE__);
            return -2;
        }

        if (err) {
            LOG_ERROR("[TcpClient:{0}]getsockopt err:{1}", __LINE__, err);
            return -3;
        }
    }

    return 0;
}

void TcpClient::notifyDataRecv(uint8_t* buffer, uint32_t bufferSize) {
    std::unique_lock<std::mutex> lock(m_tcpClientObserversMutex);
    for (auto ob : m_tcpClientObservers) {
        ob->onDataRecv(buffer, bufferSize);
    }
}

void TcpClient::notifyConnected(const std::string& serverIp, uint16_t serverPort) {
    std::unique_lock<std::mutex> lock(m_tcpClientObserversMutex);
    for (auto ob : m_tcpClientObservers) {
        ob->onConnected(serverIp, serverPort);
    }
}

void TcpClient::notifyDisconnected(const std::string& serverIp, uint16_t serverPort) {
    std::unique_lock<std::mutex> lock(m_tcpClientObserversMutex);
    for (auto ob : m_tcpClientObservers) {
        ob->onDisconnected(serverIp, serverPort);
    }
}
void TcpClient::slotTimerOut() {
    LOG_INFO("[slotTimerOut:{0}] timer stop", __LINE__);
    m_isTimerOut = true;
    m_executor.submit([this]() {
        if (m_timer->isActive()) {
            m_timer->stop();
        }
    });
}
}  // namespace intellBoxSDK
