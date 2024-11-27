#include "SHA512.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

// constants
const uint64_t SHA512::K[80] = { 
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// initial hash values
const uint64_t SHA512::H0[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// utility functions
uint64_t SHA512::ROTR(uint64_t x, uint64_t n) { 
    return (x >> n) | (x << (64 - n));  // right rotation
}

uint64_t SHA512::SHR(uint64_t x, uint64_t n) { 
    return x >> n; // right shift
}

uint64_t SHA512::Ch(uint64_t x, uint64_t y, uint64_t z) { 
    return (x & y) ^ (~x & z); // choice function
}

uint64_t SHA512::Maj(uint64_t x, uint64_t y, uint64_t z) { 
    return (x & y) ^ (x & z) ^ (y & z); // majority function
}

uint64_t SHA512::sigma0(uint64_t x) { 
    return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7); // lowercase (sigma0) 
}

uint64_t SHA512::Sigma0(uint64_t x) { 
    return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39); // uppercase (sigma0)
}

uint64_t SHA512::sigma1(uint64_t x) { 
    return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6); // lowercase (sigma1)
}

uint64_t SHA512::Sigma1(uint64_t x) { 
    return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41); // uppercase (sigma1)
}

// data padding
std::vector<uint8_t> SHA512::paddata(const std::string &data) {
    uint64_t dataBits = data.size() * 8; // data length
    std::vector<uint8_t> padded(data.begin(), data.end());

    padded.push_back(0x80); // append 1 bit
    while ((padded.size() + 8) % 128 != 0) {
        padded.push_back(0x00); // append 0 bit, align with 128 byte boundry
    }

    // append data as big endian
    for (int i = 7; i >= 0; --i) {
        padded.push_back((dataBits >> (i * 8)) & 0xff);
    }

    return padded;
}

// main hashing
std::string SHA512::hash(const std::string &data) {
    // initialize variables
    uint64_t H[8];
    std::memcpy(H, H0, sizeof(H0));

    // pad data
    std::vector<uint8_t> paddeddata = paddata(data);

    // process chunks
    for (size_t chunk = 0; chunk < paddeddata.size(); chunk += 128) {
        uint64_t W[80] = {0}; // schedule array

        // load chunk into first 16 words
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint64_t>(paddeddata[chunk + i * 8]) << 56) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 1]) << 48) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 2]) << 40) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 3]) << 32) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 4]) << 24) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 5]) << 16) |
                   (static_cast<uint64_t>(paddeddata[chunk + i * 8 + 6]) << 8) |
                   static_cast<uint64_t>(paddeddata[chunk + i * 8 + 7]);
        }

        // extend 16 into remaining 64
        for (int i = 16; i < 80; ++i) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }

        // initialize variables for chunk
        uint64_t a = H[0], b = H[1], c = H[2], d = H[3];
        uint64_t e = H[4], f = H[5], g = H[6], h = H[7];

        // main loop
        for (int i = 0; i < 80; ++i) {
            uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
            uint64_t T2 = Sigma0(a) + Maj(a, b, c);
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
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // finalize hash
    std::ostringstream hash;
    for (int i = 0; i < 8; ++i) {
        hash << std::hex << std::setw(16) << std::setfill('0') << H[i];
    }
    return hash.str();
}
