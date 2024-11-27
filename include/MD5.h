#ifndef MD5_H
#define MD5_H

#include <string>
#include <vector>
#include <cstdint>

// define MD5
class MD5 {
public:
    // compute hash based on input
    static std::string hash(const std::string& input);

private:
    // function to pad the input
    static std::vector<uint8_t> paddata(const std::string& data);

    // function to process 512-bit block 
    static void processBlock(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, const uint8_t* block);

    // function to perform a left bitwise rotation
    static uint32_t leftRotate(uint32_t x, uint32_t n);
};

#endif // MD5_H
