#include "HashLite.h"
#include <iostream>

int main() {
    std::string input = "Hello, World!"; // define text to be hashed

    HashLite sha256(HashAlgorithm::SHA256); // initialize algorithm (in this case SHA-256)

    std::cout << "SHA256 Hash: " << sha256.computeHash(input) << std::endl; // hash the text using specified algorithm

}
