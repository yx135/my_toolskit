#include "Algorithms/Algorithms.h"
#include <iostream>

int main() {
    my_toolskit::Algorithms algo;
    
    // 1. GZip 压缩/解压缩示例
    std::string original = "Hello World! This is a test string for GZip compression.";
    std::string compressed, decompressed;
    
    std::cout << "Original string: " << original << std::endl;
    
    if (algo.compressByGZip(original, compressed) == my_toolskit::Error::SUCCESS) {
        std::cout << "Compression successful. Compressed size: " << compressed.size() << std::endl;
        
        if (algo.decompressByGZip(compressed, decompressed) == my_toolskit::Error::SUCCESS) {
            std::cout << "Decompression successful." << std::endl;
            std::cout << "Decompressed string: " << decompressed << std::endl;
        }
    }
    
    // 2. Base64 编码/解码示例
    std::string text = "Hello World! This is a Base64 encoding test.";
    std::cout << "\nOriginal text: " << text << std::endl;
    
    // 字符串编码
    std::string encoded = algo.base64Encode(text);
    std::cout << "Base64 encoded: " << encoded << std::endl;
    
    // 字符串解码
    std::string decoded = algo.base64Decode(encoded, true);
    std::cout << "Base64 decoded: " << decoded << std::endl;
    
    // 二进制数据示例
    std::vector<uint8_t> binary_data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello" in hex
    std::string encoded_binary = algo.base64Encode(binary_data);
    std::cout << "\nBinary data Base64 encoded: " << encoded_binary << std::endl;
    
    std::vector<uint8_t> decoded_binary = algo.base64Decode(encoded_binary);
    std::cout << "Binary data decoded (hex): ";
    for (uint8_t byte : decoded_binary) {
        printf("%02X ", byte);
    }
    std::cout << std::endl;
    
    return 0;
} 