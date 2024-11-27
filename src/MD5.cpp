#include "MD5.h"
#include <cstring>
#include <cstdio>

// rotate bits left
uint32_t MD5::leftRotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// pad data to make its length congruent to 448 mod 512
std::vector<uint8_t> MD5::paddata(const std::string& data) {
    std::vector<uint8_t> padded(data.begin(), data.end());
    padded.push_back(0x80); // append '1' followed by '0's (0x80)

    // add zeros until length congruent to 448 mod 512
    while ((padded.size() * 8) % 512 != 448) {
        padded.push_back(0x00);
    }

    // append the original length in bits as little-endian value
    uint64_t dataBitLength = data.size() * 8;
    for (int i = 0; i < 8; ++i) {
        padded.push_back(static_cast<uint8_t>(dataBitLength >> (i * 8)));
    }

    return padded;
}

// process block
void MD5::processBlock(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, const uint8_t* block) {
    // Predefined constants
    static const uint32_t T[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    // Predefined shift amounts
    static const uint32_t S[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };

    // decode block into integer
    uint32_t X[16];
    for (int i = 0; i < 16; ++i) {
        X[i] = (block[i * 4]) | (block[i * 4 + 1] << 8) |
               (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
    }

    // initialize variables
    uint32_t a = A, b = B, c = C, d = D;

    // md5 transformation loop
    for (int i = 0; i < 64; ++i) {
        uint32_t f, g;

        // compute function based on round
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }

        // update variables
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + leftRotate(a + f + X[g] + T[i], S[i]);
        a = temp;
    }

    // update hash values
    A += a;
    B += b;
    C += c;
    D += d;
}

// compute hash
std::string MD5::hash(const std::string& input) {
    // initialize hasv values with constants
    uint32_t A = 0x67452301;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;

    // pad input data
    auto padded = paddata(input);

    // process each block of padded data
    for (size_t i = 0; i < padded.size(); i += 64) {
        processBlock(A, B, C, D, &padded[i]);
    }

    // combine hash values into full hash
    uint8_t hash[16];
    memcpy(hash, &A, 4);
    memcpy(hash + 4, &B, 4);
    memcpy(hash + 8, &C, 4);
    memcpy(hash + 12, &D, 4);

    // convert bytes into hex 
    std::string result;
    for (uint8_t byte : hash) {
        char buf[3];
        sprintf(buf, "%02x", byte);
        result += buf;
    }

    return result;
}
