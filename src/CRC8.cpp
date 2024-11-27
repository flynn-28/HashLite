#include "CRC8.h" // algorithm header
#include <sstream>  // implementing hex strings
#include <iomanip>  // hex formating
#include <cstdint>

// CRC8 constructor
CRC8::CRC8() {}

// CRC8 calculation
uint8_t CRC8::calculate(const std::string& data) const {
    uint8_t crc = CRC8_INITIAL; // Initialize algorithm

    // iterate each byte of data
    for (char c : data) {
        crc ^= static_cast<uint8_t>(c); // XOR byte against crc value

        // Process each bit
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x80) {  // check highest bit
                // Shift left and XOR against CRC8 polynomial
                crc = (crc << 1) ^ CRC8_POLYNOMIAL;
            } else {
                // else shift bits to left
                crc <<= 1;
            }
        }
    }

    return crc; // Return CRC value
}

// return hash
std::string CRC8::hash(const std::string& input) {
    uint8_t crcValue = calculate(input);  // Calculate hash
    std::ostringstream result;

    // hash to hex
    result << std::uppercase << std::hex << static_cast<int>(crcValue);

    return result.str();  // return hash
}
