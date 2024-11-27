#include "CRC16.h" // algorithm header
#include <sstream> // hash in caps
#include <iomanip> // hex formating
#include <cstdint>

// CRC16 constructor
CRC16::CRC16() {}

// CRC16 calculation
uint16_t CRC16::calculate(const std::string& data) const {
    uint16_t crc = 0x0; // Initialize at 0x0

    // Iterate each byte
    for (char c : data) {
        crc ^= (static_cast<uint16_t>(c) << 8); // shift left to align byte

        // Process each bit
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 0x8000) {  // Check most significant bit(MSB) is set
                // if MSB set, shift left and XOR against polynomial
                crc = (crc << 1) ^ CRC16_CCITT_POLYNOMIAL;
            } else {
                // if MSB not set, only shift left
                crc = crc << 1;
            }
        }
    }

    return crc;  // Return crc value
}

// return hash
std::string CRC16::hash(const std::string& input) {
    uint16_t crcValue = calculate(input);  // calculate hash
    std::ostringstream result;

    // format hash
    result << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << crcValue;

    return result.str();  // return hash
}
