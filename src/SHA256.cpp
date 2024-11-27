#include "SHA256.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

// constants
const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// rotate bits right n times
uint32_t SHA256::rotateRight(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// picks f or g based on e
uint32_t SHA256::choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

// computes majority bits from a,b,c
uint32_t SHA256::majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

// combines 3 rotated versions of x
uint32_t SHA256::sigma0(uint32_t x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

// combines 3 rotated versions of x=
uint32_t SHA256::sigma1(uint32_t x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

// combines 2 rotated versions of x
uint32_t SHA256::smallSigma0(uint32_t x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

// combines 2 rotated versions of x
uint32_t SHA256::smallSigma1(uint32_t x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

// pad data
std::vector<uint8_t> SHA256::paddata(const std::string& data) {
    std::vector<uint8_t> padded(data.begin(), data.end());
    size_t originalSize = padded.size() * 8; // original size

    // Append a '1'
    padded.push_back(0x80);

    // add 0's until size congruent to 448 mod 512
    while ((padded.size() * 8) % 512 != 448) {
        padded.push_back(0x00);
    }

    // append original size as big-endian
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>((originalSize >> (i * 8)) & 0xFF));
    }

    return padded;
}

// process block
void SHA256::processBlock(const std::vector<uint8_t>& block, uint32_t hashValues[8]) {
    uint32_t W[64]; // data schedule array
    for (size_t i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    // extend 16 words into last 48
    for (size_t i = 16; i < 64; ++i) {
        W[i] = smallSigma1(W[i - 2]) + W[i - 7] + smallSigma0(W[i - 15]) + W[i - 16];
    }

    // initialize variables
    uint32_t a = hashValues[0];
    uint32_t b = hashValues[1];
    uint32_t c = hashValues[2];
    uint32_t d = hashValues[3];
    uint32_t e = hashValues[4];
    uint32_t f = hashValues[5];
    uint32_t g = hashValues[6];
    uint32_t h = hashValues[7];

    // main hash compution
    for (size_t i = 0; i < 64; ++i) {
        uint32_t T1 = h + sigma1(e) + choose(e, f, g) + K[i] + W[i];
        uint32_t T2 = sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // update hash values
    hashValues[0] += a;
    hashValues[1] += b;
    hashValues[2] += c;
    hashValues[3] += d;
    hashValues[4] += e;
    hashValues[5] += f;
    hashValues[6] += g;
    hashValues[7] += h;
}

// compute hash
std::string SHA256::hash(const std::string& data) {
    // initialize hash values
    uint32_t hashValues[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // pad data
    std::vector<uint8_t> paddeddata = paddata(data);

    // process block
    for (size_t i = 0; i < paddeddata.size(); i += 64) {
        std::vector<uint8_t> block(paddeddata.begin() + i, paddeddata.begin() + i + 64);
        processBlock(block, hashValues);
    }

    // format hash as hex
    std::ostringstream result;
    for (uint32_t h : hashValues) {
        result << std::hex << std::setw(8) << std::setfill('0') << h;
    }

    return result.str();
}
