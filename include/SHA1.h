#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <cstdint>

// define sha1 class
class SHA1 {
public:
    // initialize object
    SHA1();

    // update hash
    void update(const std::string& data);

    // finalize and return hash
    std::string final();

    // compute hash
    static std::string hash(const std::string& input);

private:
    // define block size
    static constexpr size_t BlockSize = 64;

    // define algorithm sate
    uint32_t state[5];

    // number of bits processed
    uint64_t bitCount;

    // Buffer data before processing
    uint8_t buffer[BlockSize];

    // current position in the buffer
    size_t bufferIndex;

    // Reset state and buffer
    void reset();

    // Pad buffer to multiple of block
    void padBuffer();

    // Process block
    void processBlock();

    // Left rotate function
    static uint32_t leftRotate(uint32_t value, size_t count);
};

#endif // SHA1_H
