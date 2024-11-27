#include "HashLite.h" // hashlite header
#include "SHA256.h" // SHA256 header
#include "MD5.h" // MD5 header
#include "CRC32.h" // CRC32 Header
#include "CRC8.h" // CRC8 header
#include "CRC16.h" // CRC16 header
#include "SHA1.h" // SHA1 header
#include "SHA224.h" // SHA224 Header
#include "SHA384.h" // SHA384 header
#include "SHA512.h" // SHA512 Header
#include <stdexcept> // Error handling

// hashlite constructor
HashLite::HashLite(HashAlgorithm algorithm) : algorithm(algorithm) {}

// compute hash based on algorithm
std::string HashLite::computeHash(const std::string& input) {
    switch (algorithm) {
        case HashAlgorithm::SHA256:{ // define algorithm
            SHA256 sha256; // create object
            return SHA256::hash(input); // return hash
        }
            case HashAlgorithm::SHA1:{ // define algorithm
            SHA1 sha1; // create object
            return SHA1::hash(input); // return hash
        }
          case HashAlgorithm::SHA224:{ // define algorithm
            SHA224 sha224;
            return SHA224::hash(input); // return hash
        }  
            case HashAlgorithm::SHA384:{ // define algorithm
            SHA384 sha384; // create object
            return SHA384::hash(input); // return hash
        }
            case HashAlgorithm::SHA512:{ // define algorithm
            SHA512 sha512; // create object
            return SHA512::hash(input); // return hash
        }
        case HashAlgorithm::MD5: { // define algorithm
            MD5 md5; // create object
            return MD5::hash(input); // return hash
        }
        case HashAlgorithm::CRC32: { // define algorithm
            CRC32 crc32; // create object
            return crc32.hash(input); // return hash
        }
        case HashAlgorithm::CRC8: { // define algorithm
            CRC8 crc8; // create object
            return crc8.hash(input); // return hash
        }
        case HashAlgorithm::CRC16: { // define algorithm
            CRC16 crc16; // create object
            return crc16.hash(input); // return hash
        }         

        default:
            throw std::runtime_error("Unsupported algorithm"); // error data for unsuported algorithm
    }
}
