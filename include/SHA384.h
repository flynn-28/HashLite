#ifndef SHA384_H
#define SHA384_H

#include <string>
#include <vector>
#include <cstdint>

// define class
class SHA384 {
public:
    // compute hash
    static std::string hash(const std::string& input);

private:
    // pad data
    static std::vector<uint8_t> paddata(const std::vector<uint8_t>& data);

    // process block
    static void processBlock(const uint8_t* block, uint64_t* H);
};

#endif // SHA384_H
