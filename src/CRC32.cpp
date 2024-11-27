#include "CRC32.h" // algorithm header
#include <iomanip> // hex formating
#include <sstream> // hash in caps
#include <cstdint>

// CRC32 constructor
CRC32::CRC32() {
    // Initialize table for all bytes
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        // Generate table using 0xEDB88320
        for (uint8_t j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320; // XOR against polynomial if the LSB is set
            } else {
                crc >>= 1; // or only shift bits
            }
        }
        table[i] = crc; // Store results in table
    }
}

// CRC32 calculation
uint32_t CRC32::calculate(const std::string& data) const {
    uint32_t crc = 0xFFFFFFFF; // Start with 0xFFFFFFFF

    // Iterate each byte
    for (unsigned char byte : data) {
        uint8_t index = static_cast<uint8_t>((crc ^ byte) & 0xFF); // index by XOR CRC and byte, then masking 0xFF
        crc = (crc >> 8) ^ table[index]; // Shift CRC and save to table
    }

    // Final XOR with 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF;
}

// return hash
std::string CRC32::hash(const std::string& input) {
    uint32_t crcValue = calculate(input); // Calculate hash
    std::ostringstream result;

    // format hash as hex
    result << std::uppercase << std::hex << crcValue;

    return result.str(); // return formated hash
}
