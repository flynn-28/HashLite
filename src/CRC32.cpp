#include "CRC32.h"
#include <iomanip> // For std::uppercase and std::hex
#include <sstream> // For converting the result to a hex string
#include <cstdint>

CRC32::CRC32() {
    // Initialize the CRC table
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint8_t j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
}

uint32_t CRC32::calculate(const std::string& data) const {
    uint32_t crc = 0xFFFFFFFF;

    for (unsigned char byte : data) {
        uint8_t index = static_cast<uint8_t>((crc ^ byte) & 0xFF);
        crc = (crc >> 8) ^ table[index];
    }

    return crc ^ 0xFFFFFFFF;
}

std::string CRC32::hash(const std::string& input) {
    uint32_t crcValue = calculate(input);
    std::ostringstream result;
    result << std::uppercase << std::hex << crcValue;
    return result.str();
}
