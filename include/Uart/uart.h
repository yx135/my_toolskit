#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum SERIAL_RET {
    SR_CHECK_FAIL = -15,
    SR_INVALID_PARA,
    SR_INVALID_FD,
    SR_AUTH_FAIL,
    SR_TIMEOUT,
    SR_ALREADY_REGISTER,
    SR_CMD_ENROLL_FAIL,
    SR_INVALID_DATA,
    SR_CMD_EXCUTE_FAIL,
    SR_GET_UNUSED_ID_FAIL,
    SR_UPLOAD_CMP_CAPTURE_FAIL,
    SR_UPLOAD_CMP_LIB_FAIL,
    SR_UPLOAD_STORAGE_LIB_FAIL,
    SR_GET_FEATURE_FAIL,
    SR_STOP_BY_APP,

    SR_SUCCESS
};

#include <pthread.h>

struct UartModule {
    int (*open)(const char* dev, int baud, int data, int check);
    int (*read)(int fd, void* buf, int bytes, unsigned int timeoutSec);
    int (*write)(int fd, char* buf, int bytes);
    void (*close)(int fd);
    void (*stopRead)(int fd);
    int fd;
};

int serialOpen(const char* dev, int baud, int data, int check);
int serialRead(int fd, void* buf, int bytes, unsigned int timeoutSec);
int serialWrite(int fd, char* buf, int bytes);
void serialStopRead(int fd);
void serialClose(int fd);

int enableSerial(void);
int enableSend(void);
int enableRecv(void);
void disableSerial();

#ifdef __cplusplus
}
#endif
