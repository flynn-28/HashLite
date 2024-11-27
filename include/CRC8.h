#ifndef CRC8_H
#define CRC8_H

#include <string>
#include <cstdint>

// Define CRC8 Class 
class CRC8 {
public:
    // initialize object
    CRC8();

    // hash input and return checksum
    std::string hash(const std::string& input);

private:
    // calculate checksum
    uint8_t calculate(const std::string& data) const;

    // define polynomial
    static constexpr uint8_t CRC8_POLYNOMIAL = 0x7;

    // define inital value
    static constexpr uint8_t CRC8_INITIAL = 0x00;
};

#endif // CRC8_H
