#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <string>
#include <cstdint>

// define class
class SHA256 {
public:
    // compute hash
    static std::string hash(const std::string& data);

private:
    // Rotate right function
    static uint32_t rotateRight(uint32_t x, uint32_t n);

    // Choose function
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g);

    // Majority function
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c);

    // Sigma0 function
    static uint32_t sigma0(uint32_t x);

    // Sigma1 function
    static uint32_t sigma1(uint32_t x);

    // SmallSigma0 function
    static uint32_t smallSigma0(uint32_t x);

    // SmallSigma1 function
    static uint32_t smallSigma1(uint32_t x);

    // Pad data
    static std::vector<uint8_t> paddata(const std::string& data);

    // Process block
    static void processBlock(const std::vector<uint8_t>& block, uint32_t hashValues[8]);

    // define constant array K
    static const uint32_t K[64];
};

#endif // SHA256_H
