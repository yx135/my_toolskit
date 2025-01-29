#pragma once

namespace my_toolskit {

enum class Error {
    SUCCESS = 0,
    FAILED = -1,
    INVALID_PARAM = -2,
    COMPRESS_ERROR = -3,
    DECOMPRESS_ERROR = -4,
    ENCODE_ERROR = -5,
    DECODE_ERROR = -6,
    INITIAL_FAIL = -7,
    GENERAL_FAIL = -8,
    MEMORY_ERROR = -9,
    FILE_ERROR = -10,
    NETWORK_ERROR = -11,
    TIMEOUT_ERROR = -12,
    PERMISSION_ERROR = -13,
    NOT_FOUND = -14,
    ALREADY_EXISTS = -15
};

} // namespace my_toolskit 