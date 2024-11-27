#include "SHA224.h"
#include <iomanip>
#include <sstream>
#include <cstring>
#include <array>
#include <cstdint>

// initialization constants 
constexpr std::array<uint32_t, 8> H_INIT = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

// round constants
constexpr std::array<uint32_t, 64> K = {
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

// constructor
SHA224::SHA224() {
    reset();
}

// reset state to initial values
void SHA224::reset() {
    std::copy(H_INIT.begin(), H_INIT.end(), state);
    bitCount = 0; // tracks processed bits
    bufferIndex = 0; // tracks buffer fill
    std::memset(buffer, 0, BlockSize); // clear buffer
}

// rotate right
uint32_t SHA224::rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// choose function based on x
uint32_t SHA224::ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

// return majority bits from x,y,z
uint32_t SHA224::maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// rotates and combines bits of x
uint32_t SHA224::sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

// rotates and combines bits of x
uint32_t SHA224::sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

// data schedule
uint32_t SHA224::gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

// messagle schedule
uint32_t SHA224::gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// update hash state
void SHA224::update(const std::string& data) {
    const uint8_t* input = reinterpret_cast<const uint8_t*>(data.data());
    size_t length = data.size();

    for (size_t i = 0; i < length; ++i) {
        buffer[bufferIndex++] = input[i];
        bitCount += 8; // increment 8 bits per byte

        if (bufferIndex == BlockSize) { // full buffer
            processBlock(buffer);
            bufferIndex = 0;
        }
    }
}


// buffer padding
void SHA224::padBuffer() {
    buffer[bufferIndex++] = 0x80; // appends 1's

    // reset buffer if no room for padding
    if (bufferIndex > BlockSize - 8) {
        while (bufferIndex < BlockSize) {
            buffer[bufferIndex++] = 0x00;
        }
        processBlock(buffer);
        bufferIndex = 0;
    }

    // append 0's in big endian
    while (bufferIndex < BlockSize - 8) {
        buffer[bufferIndex++] = 0x00;
    }

    uint64_t bitCountBE = bitCount;
    for (int i = 7; i >= 0; --i) {
        buffer[bufferIndex++] = (bitCountBE >> (i * 8)) & 0xFF;
    }
    processBlock(buffer);
}

// process block
void SHA224::processBlock(const uint8_t block[BlockSize]) {
    uint32_t W[64];

    // load first 16 words of W
    for (int t = 0; t < 16; ++t) {
        W[t] = (block[t * 4] << 24) |
               (block[t * 4 + 1] << 16) |
               (block[t * 4 + 2] << 8) |
               (block[t * 4 + 3]);
    }

    // expand to 64 words
    for (int t = 16; t < 64; ++t) {
        W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
    }

    // initialize variables
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // main loop, 64 rounds
    for (int t = 0; t < 64; ++t) {
        uint32_t T1 = h + sigma1(e) + ch(e, f, g) + K[t] + W[t];
        uint32_t T2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}


// finaliz hash
std::string SHA224::final() {
    padBuffer();

    // convert state to string (first 7 words)
    std::ostringstream result;
    for (size_t i = 0; i < 7; ++i) { 
        result << std::hex << std::setfill('0') << std::setw(8) << state[i];
    }
    return result.str();
}

// calculate hash
std::string SHA224::hash(const std::string& input) {
    SHA224 sha224;
    sha224.update(input);
    return sha224.final();
}
