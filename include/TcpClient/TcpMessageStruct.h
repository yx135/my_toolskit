#include <stdint.h>
#pragma once
namespace intellBoxSDK {

#define PACKET_VERSION1 0x00
#define PACKET_VERSION2 0x01
#define PACKET_MAX_SIZE (256 * 1024)
#define PACKET_MIN_SIZE 11  // 2+1+1+2+1+4
#define PACKET_DATA_SIZE (PACKET_MAX_SIZE - PACKET_MIN_SIZE)
#define PACKET_HEAD_LEN 7
#define SEND_QUEUE_SIZE (8 * 1024 * 1024)
#define RECV_QUEUE_SIZE (8 * 1024 * 1024)
#define SEND_BUFFER_SIZE PACKET_MAX_SIZE
#define RECV_BUFFER_SIZE PACKET_MAX_SIZE
#define TIMEOUT_CNT 15

#define BIGWORD(h, l) uint16_t(((h) << 8) | (l))
#define BIGDWORD(hh, hl, lh, ll) unsigned(((hh) << 24) | ((hl) << 16) | ((lh) << 8) | (ll))

#pragma pack(push, 1)
struct TcpMessage {
    unsigned short m_version;  // 2
    unsigned char m_type;      // 1
    unsigned short m_id;       // 2
    unsigned char m_encrypt;   // 1
    unsigned char m_crc;       // 1
    unsigned int m_dataLen;    // 4
    unsigned char m_data[PACKET_DATA_SIZE];
    unsigned dataLen() const {
        return bigDword(m_dataLen);
    }
    static uint32_t bigDword(uint32_t num) {
        const uint8_t* pb = reinterpret_cast<const unsigned char*>(&num);
        return (
            (static_cast<uint32_t>(pb[0]) << 24) | (static_cast<uint32_t>(pb[1]) << 16) |
            (static_cast<uint32_t>(pb[2]) << 8) | static_cast<uint32_t>(pb[3]));
    }
    unsigned packetLen() const {
        return dataLen() + PACKET_MIN_SIZE;
    }
};
#pragma pack(pop)
typedef struct TcpMessage SPacket;

}  // namespace intellBoxSDK
