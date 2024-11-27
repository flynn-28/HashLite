#include "HashLite.h" 
#include <iostream>
#include <fstream>
#include <sstream>     

int main() {
    std::string filename = "example.txt";  // define file
    std::ifstream file(filename, std::ios::binary);  // open file as binary

    std::stringstream buffer;   //  create object to hold string
    buffer << file.rdbuf();     // copy files binary to object
    std::string fileContent = buffer.str();  // convert binary into string

    std::cout << HashAlgorithm::CRC32.computeHash(fileContent) << std::endl;  // compute and print hash

    file.close(); // close file
    return 0;
}
