#ifndef CRC32_H
#define CRC32_H

#include <string>
#include <cstdint>

// define CRC32 class
class CRC32 {
public:
    // initialize object
    CRC32();

    // hash input and return checksum
    std::string hash(const std::string& input);

private:
    // calculate checksum
    uint32_t calculate(const std::string& data) const;
    // define table
    uint32_t table[256];
};

#endif // CRC32_H
