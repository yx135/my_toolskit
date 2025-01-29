#pragma once

#include <string>

namespace my_toolskit {

enum class Error {
    /// the operation is successful
    SUCCESS = 0,

    /// general fzail
    GENERAL_FAIL = -1,

    /// initial fail
    INITIAL_FAIL = -2,

    /// the device is not connected
    CONNECTION_FAIL = -3,

    /// the device is broken
    DEVCIE_FAIL = -4,

    /// verify fail
    VERIFY_FAIL = -5,

    /// the input para is invalid
    INVALID_PARA = -6,

    /// the device is not existed
    NO_SUCH_DEVICE = -7,

    /// the operation is not processing
    NO_SUCH_OPERATE = -8,

    /// no such user
    NO_SUCH_USER = -9,

    /// no access to the operation
    NO_AUTHORITY = -10,

    /// no enough space
    NO_ENOUGH_SPACE = -11,

    /// the operation is time out
    TIMEOUT = -12,

    /// the operation is processing
    PROCESSING = -13,

    /// the operation is stopped by user
    STOP_BY_USER = -14,

    /// send data to client fail
    SEND_FAIL = -15,

    /// write db fail
    DB_FAIL = -16,

    /// not support
    NOT_SUPPORT = -17,

    /// the record is not exist
    NO_SUCH_RECORD = -18,

    /// the name is exist
    NAME_EXIST = -19,

    /// the system must have one administrator
    ONLY_ADMIN = -20,

    /// the device is warning
    WARNING = -21,

    /// the wrong dirction
    WRONG_DIRECTION = -22,

    /// door opened
    DOOR_OPENED = -23,

    /// no need process
    NO_NEED_PROCESS = -24,

    /// has logined
    HAS_LOGINED = -25
};

const std::string& getErrorString(Error err);

}  // namespace my_toolskit
