#ifndef CRC16_H
#define CRC16_H

#include <string>
#include <cstdint>
// METHOD: CRC16_CCIT_ZERO
// define CRC16 class
class CRC16 {
public:
    // initialize object
    CRC16();

    // hash input and return checksum
    std::string hash(const std::string& input);

private:
    // calculate checksum
    uint16_t calculate(const std::string& data) const;

    // define polynomial
    static constexpr uint16_t CRC16_CCITT_POLYNOMIAL = 0x1021;
};

#endif // CRC16_H
