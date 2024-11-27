#ifndef HASHLITE_H
#define HASHLITE_H

#include <string>
#include <cstdint>

// define available algorithms
enum class HashAlgorithm {
    SHA256,    // SHA-256 algorithm
    MD5,       // MD5 algorithm
    CRC32,     // CRC32 algorithm
    CRC8,      // CRC8 algorithm
    CRC16,     // CRC16 algorithm
    SHA1,      // SHA-1 algorithm
    SHA224,    // SHA-224 algorithm
    SHA384,    // SHA-384 algorithm
    SHA512,    // SHA-512 algorithm
};

// define class
class HashLite {
public:
    // initialize object with selected algorithm
    HashLite(HashAlgorithm algorithm);

    // compute and return hash of the input using selected algorithm
    std::string computeHash(const std::string& input);

private:
    // return selected algorithm  
    HashAlgorithm algorithm;
};

#endif // HASHLITE_H
