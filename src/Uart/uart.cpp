#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <termios.h>
#include <stdbool.h>
#include <math.h>

#include <sys/epoll.h>
#include <errno.h>

#include <map>
#include <vector>
#include <memory>

#include "IntellBoxCommon/Utils/Uart/uart.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"

#define NAME_LEN 128
#define EPOLL_WAIT_TIMEOUT 3000
#define SEND_GPIO_EXPORT "echo 221 > /sys/class/gpio/export 2>/dev/null"
#define SEND_GPIO_DIRECTION "echo out > /sys/class/gpio/gpio221/direction 2>/dev/null"
#define SEND_GPIO_VALUE "echo 1 > /sys/class/gpio/gpio221/value 2>/dev/null"
#define READ_GPIO_VALUE "echo 0 > /sys/class/gpio/gpio221/value 2>/dev/null"
#define SEND_GPIO_EXPORT_RELEASE "echo 221 > /sys/class/gpio/unexport 2>/dev/null"

static struct _ManagerInfo {
    pthread_t tid;
    int epfd;
    bool closeFlag;
} ManagerInfo;

struct UartInfo {
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    char devName[NAME_LEN];
    bool stopFlag;
    unsigned int readSize;
    unsigned int payloadSize;
    char* payload;
};

std::map<int, std::shared_ptr<struct UartInfo>> g_readingCondVar;

static void* uartManager(void*) {
    int epfds = -1;
    bool hasRecv = false;
    unsigned int epCounts = 0;
    std::vector<struct epoll_event> epEvent;

    while (!ManagerInfo.closeFlag) {
        epCounts = g_readingCondVar.size();
        if (epCounts != epEvent.size()) {
            epEvent.resize(epCounts);
        }

        epfds = epoll_wait(ManagerInfo.epfd, epEvent.data(), epCounts, EPOLL_WAIT_TIMEOUT);
        if (0 < epfds) {
            if (!hasRecv) hasRecv = true;
            for (int i = 0; i < epfds; i++) {
                int size = -1;
                int index = epEvent[i].data.fd;

                if (0 == g_readingCondVar.count(index)) {
                    continue;
                }

                std::shared_ptr<struct UartInfo> ui = g_readingCondVar[index];
                char* readData = ui->payload;
                size_t nbytes = ui->readSize;

                while (true) {
                    if (ui->payloadSize >= nbytes) {
                        ui->payloadSize = nbytes;
                        break;
                    }

                    size = read(epEvent[i].data.fd, readData + ui->payloadSize, nbytes);
                    if (-1 == size) {
                        LOG_ERROR("[{0}][{1}]serial read size wrong.", __FUNCTION__, __LINE__);
                        break;
                    }
                    if (size == 0) {
                        break;
                    }
                    ui->payloadSize += size;
                }

                if (ui->payloadSize < nbytes) {
                    LOG_DEBUG("[{0}][{1}]serial read continue.", __FUNCTION__, __LINE__);
                    continue;
                }

                pthread_mutex_lock(&ui->mutex);
                pthread_cond_signal(&ui->cond);
                pthread_mutex_unlock(&ui->mutex);
            }
            continue;
        } else if (0 == epfds) {
            LOG_DEBUG("[{0}][{1}]epoll timeout. hasRecv: {2}", __FUNCTION__, __LINE__, hasRecv);
            if (hasRecv) {
                for (auto cond : g_readingCondVar) {
                    auto ui = cond.second;
                    pthread_mutex_lock(&ui->mutex);
                    pthread_cond_signal(&ui->cond);
                    pthread_mutex_unlock(&ui->mutex);
                }
            }
        } else if (-1 == epfds) {
            perror("epoll_wait");

            //@Reduce the frequency of epoll detection
            sleep(1);
        }
        hasRecv = false;
    }
    LOG_INFO("[{0}][{1}]epoll manager exit.", __FUNCTION__, __LINE__);
    return nullptr;
}

static bool initEpoll() {
    if (0 < ManagerInfo.epfd) {
        LOG_INFO("[{0}][{1}]initiliaze finished.", __FUNCTION__, __LINE__);
        return true;
    }

    ManagerInfo.epfd = epoll_create(1);
    if (-1 == ManagerInfo.epfd) {
        perror("epoll_create");
        return false;
    }

    ManagerInfo.closeFlag = false;

    if (0 != pthread_create(&ManagerInfo.tid, NULL, uartManager, NULL)) {
        perror("pthread_create");
        return false;
    }

    return true;
}

static void destroyEpoll() {
    close(ManagerInfo.epfd);

    ManagerInfo.closeFlag = true;

    pthread_join(ManagerInfo.tid, NULL);

    g_readingCondVar.clear();
}

static int serialSetOpt(int fd, int nSpeed, int nBits, char nEvent, int nStop) {
    struct termios newtio, oldtio;

    if (tcgetattr(fd, &oldtio) != 0) {
        perror("tcgetattr");
        return -1;
    }
    bzero(&newtio, sizeof(newtio));

    newtio.c_cflag |= CLOCAL | CREAD;
    newtio.c_cflag &= ~CSIZE;

    switch (nBits) {
        case 7:
            newtio.c_cflag |= CS7;
            break;
        case 8:
            newtio.c_cflag |= CS8;
            break;
    }

    switch (nEvent) {
        case 'O':
            newtio.c_cflag |= PARENB;
            newtio.c_cflag |= PARODD;
            newtio.c_iflag |= (INPCK | ISTRIP);
            break;
        case 'E':
            newtio.c_iflag |= (INPCK | ISTRIP);
            newtio.c_cflag |= PARENB;
            newtio.c_cflag &= ~PARODD;
            break;
        case 'N':
            newtio.c_cflag &= ~PARENB;
            break;
    }

    switch (nSpeed) {
        case 2400:
            cfsetispeed(&newtio, B2400);
            cfsetospeed(&newtio, B2400);
            break;
        case 4800:
            cfsetispeed(&newtio, B4800);
            cfsetospeed(&newtio, B4800);
            break;
        case 9600:
            cfsetispeed(&newtio, B9600);
            cfsetospeed(&newtio, B9600);
            break;
        case 115200:
            cfsetispeed(&newtio, B115200);
            cfsetospeed(&newtio, B115200);
            break;
        case 460800:
            cfsetispeed(&newtio, B460800);
            cfsetospeed(&newtio, B460800);
            break;

        case 19200:
            cfsetispeed(&newtio, B19200);
            cfsetospeed(&newtio, B19200);
            break;

        default:
            cfsetispeed(&newtio, B9600);
            cfsetospeed(&newtio, B9600);
            break;
    }

    if (nStop == 1) {
        newtio.c_cflag &= ~CSTOPB;
    } else if (nStop == 2) {
        newtio.c_cflag |= CSTOPB;
    }

    newtio.c_cc[VTIME] = 0;
    newtio.c_cc[VMIN] = 0;

    tcflush(fd, TCIFLUSH);

    if ((tcsetattr(fd, TCSANOW, &newtio)) != 0) {
        perror("tcsetattr");
        return -1;
    }

    return 0;
}

static int serialTcflush(int fd) {
    return tcflush(fd, TCIFLUSH);
}

static int serialInit(const char* dev) {
    int fd;

    for (auto readingCondVar : g_readingCondVar) {
        if (0 == strncmp(readingCondVar.second->devName, dev, strlen(dev))) {
            LOG_WARN("[{0}][{1}]{2} is busy, New other.", __FUNCTION__, __LINE__, dev);
        }
    }

    fd = open(dev, O_RDWR | O_NOCTTY);
    if (-1 == fd) {
        LOG_ERROR("[{0}][{1}]Open {2} failed.", __FUNCTION__, __LINE__, dev);
        return -1;
    }

    if (fcntl(fd, F_SETFL, 0) < 0) {
        close(fd);
        perror("fcntl");
        return -1;
    }

    if (!initEpoll()) {
        close(fd);
        return -1;
    }

    return fd;
}

int serialOpen(const char* dev, int baud, int data, int check) {
    int fd = -1;
    size_t devLen = strlen(dev);
    std::shared_ptr<struct UartInfo> ui = std::make_shared<struct UartInfo>();
    if (nullptr == ui) {
        perror("make_shared");
        return -1;
    }

    fd = serialInit(dev);
    if (0 > fd) {
        perror("serialInit");
        return -1;
    }

    if (serialSetOpt(fd, baud, data, 'N', check) < 0) {
        perror("set_opt");
        close(fd);
        return -1;
    }

    memcpy(ui->devName, dev, devLen);
    ui->devName[devLen] = '\0';

    if (0 != pthread_cond_init(&ui->cond, NULL)) {
        LOG_ERROR("[{0}][{1}]Create condition variable failed.", __FUNCTION__, __LINE__);
        close(fd);
        return -1;
    }

    pthread_mutex_init(&ui->mutex, NULL);

    g_readingCondVar.insert(std::make_pair(fd, ui));

    return fd;
}

int serialRead(int fd, void* buf, int bytes, unsigned int timeoutSec) {
    int retVal = -1;
    struct timespec tm;
    std::shared_ptr<struct UartInfo> ui;
    memset(&tm, '\0', sizeof(struct timespec));

    if (0 == g_readingCondVar.count(fd)) {
        LOG_ERROR("[{0}][{1}]{2} invalid.", __FUNCTION__, __LINE__, fd);
        return SR_CHECK_FAIL;
    }

    ui = g_readingCondVar[fd];
    ui->payloadSize = 0;
    ui->readSize = bytes;
    ui->payload = (char*)buf;

    struct epoll_event epEvent;
    epEvent.events = EPOLLIN;
    epEvent.data.fd = fd;
    if (-1 == epoll_ctl(ManagerInfo.epfd, EPOLL_CTL_ADD, fd, &epEvent)) {
        perror("epoll_ctl");
        return SR_CHECK_FAIL;
    }

    ui->stopFlag = false;

    pthread_mutex_lock(&ui->mutex);
    clock_gettime(CLOCK_REALTIME, &tm);
    tm.tv_sec += timeoutSec / 1000;
    tm.tv_nsec += (timeoutSec % 1000) * pow(10, 6);

    retVal = pthread_cond_timedwait(&ui->cond, &ui->mutex, &tm);

    if (-1 == epoll_ctl(ManagerInfo.epfd, EPOLL_CTL_DEL, fd, &epEvent)) {
        pthread_mutex_unlock(&ui->mutex);
        perror("epoll_ctl");
        return SR_CHECK_FAIL;
    }

    if (0 == retVal && ui->stopFlag) {
        pthread_mutex_unlock(&ui->mutex);
        LOG_ERROR("[{0}][{1}]serial read stop by user.", __FUNCTION__, __LINE__);
        return SR_STOP_BY_APP;
    }

    if (ETIMEDOUT == retVal) {
        pthread_mutex_unlock(&ui->mutex);
        if (ui->payloadSize > 0) {
            return ui->payloadSize;
        }
        LOG_ERROR("[{0}][{1}]serial read timeout.", __FUNCTION__, __LINE__);
        return SR_TIMEOUT;
    }
    pthread_mutex_unlock(&ui->mutex);

    return ui->payloadSize;
}

int serialWrite(int fd, char* buf, int bytes) {
    int writeSize = 0, size = 0;

    if (0 == g_readingCondVar.count(fd)) {
        LOG_ERROR("[{0}][{1}]{2} not initialize", __FUNCTION__, __LINE__, fd);
        return -1;
    }

    serialTcflush(fd);

    while (writeSize < bytes) {
        size = write(fd, buf, bytes);
        if (size < 0) {
            perror("write");
            return writeSize;
        }
        writeSize += size;
    }

    return writeSize;
}

void serialStopRead(int fd) {
    if (0 == g_readingCondVar.count(fd)) {
        LOG_INFO("[{0}][{1}]{2} not initialize", __FUNCTION__, __LINE__, fd);
        return;
    }

    std::shared_ptr<struct UartInfo> ui = g_readingCondVar[fd];
    pthread_mutex_lock(&ui->mutex);
    ui->stopFlag = true;
    pthread_cond_signal(&ui->cond);
    pthread_mutex_unlock(&ui->mutex);
}

void serialClose(int fd) {
    std::map<int, std::shared_ptr<struct UartInfo>>::iterator readingCondVar = g_readingCondVar.find(fd);
    if (readingCondVar == g_readingCondVar.end()) {
        LOG_INFO("[{0}][{1}]{2} not initialize", __FUNCTION__, __LINE__, fd);
        return;
    }

    close(fd);

    std::shared_ptr<struct UartInfo> ui = g_readingCondVar[fd];
    pthread_cond_destroy(&ui->cond);
    pthread_mutex_destroy(&ui->mutex);

    g_readingCondVar.erase(readingCondVar);

    if (!g_readingCondVar.empty()) {
        return;
    }

    destroyEpoll();
}

int enableSerial(void) {
    int times = 3;
    while (0 != system(SEND_GPIO_EXPORT)) {
        //@Reduce control operation frequency
        usleep(600);
        if (times-- < 0) {
            break;
        }
    }
    return system(SEND_GPIO_DIRECTION);
}

int enableSend(void) {
    return system(SEND_GPIO_VALUE);
}

int enableRecv(void) {
    return system(READ_GPIO_VALUE);
}

void disableSerial() {
    int times = 3;
    while (0 != system(SEND_GPIO_EXPORT_RELEASE)) {
        //@Reduce control operation frequency
        usleep(600);
        if (times-- < 0) {
            break;
        }
    }
}
