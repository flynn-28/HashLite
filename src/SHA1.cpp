#include "SHA1.h"
#include <sstream>
#include <iomanip>
#include <cstring> 

// sha1 constructor
SHA1::SHA1() {
    reset();
}

// reset object state
void SHA1::reset() {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;

    bitCount = 0;
    bufferIndex = 0;
    std::memset(buffer, 0, BlockSize);
}

// rotate left
uint32_t SHA1::leftRotate(uint32_t value, size_t count) {
    return (value << count) | (value >> (32 - count));
}

// update state
void SHA1::update(const std::string& data) {
    const uint8_t* input = reinterpret_cast<const uint8_t*>(data.data());
    size_t length = data.size();

    for (size_t i = 0; i < length; ++i) {
        buffer[bufferIndex++] = input[i];
        bitCount += 8; // increment count

        if (bufferIndex == BlockSize) { // full buffer processing
            processBlock();
            bufferIndex = 0;
        }
    }
}

// pad buffer
void SHA1::padBuffer() {
    buffer[bufferIndex++] = 0x80; // append "1"

    // process block if no space for buffer
    if (bufferIndex > BlockSize - 8) {
        while (bufferIndex < BlockSize) {
            buffer[bufferIndex++] = 0x00;
        }
        processBlock();
        bufferIndex = 0;
    }

    // pad with 0's
    while (bufferIndex < BlockSize - 8) {
        buffer[bufferIndex++] = 0x00;
    }

    // append bit count in big endian
    uint64_t bitCountBE = bitCount;
    for (int i = 7; i >= 0; --i) {
        buffer[bufferIndex++] = (bitCountBE >> (i * 8)) & 0xFF;
    }
}

// process block
void SHA1::processBlock() {
    uint32_t w[80];

    // initialize 16 words from buffer
    for (size_t i = 0; i < 16; ++i) {
        w[i] = (buffer[i * 4] << 24) |
               (buffer[i * 4 + 1] << 16) |
               (buffer[i * 4 + 2] << 8) |
               (buffer[i * 4 + 3]);
    }

    // extend 16 words to 80
    for (size_t i = 16; i < 80; ++i) {
        w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    // initialize variables
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    // main loop
    for (size_t i = 0; i < 80; ++i) {
        uint32_t f, k;

        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = leftRotate(b, 30);
        b = a;
        a = temp;
    }

    // add variables to state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    // clear buffer
    bufferIndex = 0;
    std::memset(buffer, 0, BlockSize);
}

// finalize hash
std::string SHA1::final() {
    padBuffer(); // add padding
    processBlock(); // process block

    // format state as hex
    std::ostringstream result;
    for (size_t i = 0; i < 5; ++i) {
        result << std::hex << std::setfill('0') << std::setw(8) << state[i];
    }

    reset(); // reset state
    return result.str();
}

// compute hash
std::string SHA1::hash(const std::string& input) {
    SHA1 sha1;
    sha1.update(input);
    return sha1.final();
}
