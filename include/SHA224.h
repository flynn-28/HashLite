#ifndef SHA224_H
#define SHA224_H

#include <string>
#include <cstdint>

// define class
class SHA224 {
public:
    // initialize object
    SHA224();

    // update hash
    void update(const std::string& data);

    // finalize hash
    std::string final();

    // compute hash
    static std::string hash(const std::string& input);

private:
    // define block size
    static constexpr size_t BlockSize = 64;

    // define output size
    static constexpr size_t OutputSize = 28;

    // define algorithm state 
    uint32_t state[8];

    // number of bits processed
    uint64_t bitCount;

    // Buffer data before processing
    uint8_t buffer[BlockSize];

    // current position in buffer
    size_t bufferIndex;

    // Reset state and buffer
    void reset();

    // Pad the buffer to multiple of block
    void padBuffer();

    // Process block
    void processBlock(const uint8_t block[BlockSize]);

    // Rotate right function 
    static uint32_t rotr(uint32_t x, uint32_t n);

    // Choose function 
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z);

    // Majority function
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z);

    // Sigma0 function 
    static uint32_t sigma0(uint32_t x);

    // Sigma1 function
    static uint32_t sigma1(uint32_t x);

    // Gamma0 function
    static uint32_t gamma0(uint32_t x);

    // Gamma1 function
    static uint32_t gamma1(uint32_t x);
};

#endif // SHA224_H
