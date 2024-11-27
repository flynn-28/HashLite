#ifndef SHA512_H
#define SHA512_H

#include <string>
#include <vector>
#include <cstdint>

// define class
class SHA512 {
public:
    // compute hash
    static std::string hash(const std::string &data);

private:
    // define constants K and H0
    static const uint64_t K[80];   // round constants
    static const uint64_t H0[8];   // Initial hash

    // Rotate right function
    static uint64_t ROTR(uint64_t x, uint64_t n);

    // Shift right function
    static uint64_t SHR(uint64_t x, uint64_t n);

    // Conditional function (Ch)
    static uint64_t Ch(uint64_t x, uint64_t y, uint64_t z);

    // Majority function (Maj)
    static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z);

    // Sigma0 function
    static uint64_t Sigma0(uint64_t x);

    // Sigma1 function
    static uint64_t Sigma1(uint64_t x);

    // Small sigma0 function
    static uint64_t sigma0(uint64_t x);

    // Small sigma1 function
    static uint64_t sigma1(uint64_t x);

    // pad data
    static std::vector<uint8_t> paddata(const std::string &data);
};

#endif // SHA512_H
