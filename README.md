# HashLite Library Documentation

## Contents
1. [Overview](#overview)
2. [Installation](#installation) <br>
   2.1 [Downloading](#downloading) <br>
   2.2 [Building From Source](#building-from-source)
    - [Linux/MacOS](#linuxmacos)
    - [Windows - MinGW](#windows---mingw)
    - [Windows - Visual Studio](#windows---visual-studio)
3. [Including Library](#include-library-in-project)
4. [Usage](#usage)
5. [Usage Examples](#usage-examples)
    - [Hashing Text](#hashing-text)
    - [Hashing a File](#hashing-a-file)
6. [Supported Algorithms](#supported-algorithms)
7. [Notes](#notes)
8. [Support](#support)
----
## Overview
**HashLite** is a lightweight and cross platform C++ library designed for implementing hashing into C++ programs. It allows users to compute hashes using several algorithms such as SHA256 and MD5 along with others.

---

## Installation
You can install HashLite by downloading a precompiled library for your system or building it from source.

### Downloading
You can download a precompiled version of the library [here](link_to_releases_page). The uncompressed folders have the following structure:
```bash
HashLite
├── include
│   ├── CRC16.h
│   ├── CRC32.h
│   ├── CRC8.h
│   ├── HashLite.h
│   ├── MD5.h
│   ├── SHA1.h
│   ├── SHA224.h
│   ├── SHA256.h
│   ├── SHA384.h
│   └── SHA512.h
└── lib
    └── libHashLite.a    # ON LINUX and MINGW BUILDS
    └── HashLite.lib     # ONLY ON VISUAL STUDIO BUILDS
```
Copy the include/ and lib/ directories to your project or system include paths.
### Building from Source

##### Linux/MacOS
1. Clone repository and open directory
```bash
git clone https://github.com/flynn-28/HashLite && cd HashLite
```
2. Make and open build directory
```bash
mkdir build && cd build
```
3. Build library
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

##### Windows - MinGW
1. Clone repository and open directory
```bash
git clone https://github.com/flynn-28/HashLite
```
2. Open Directory
```bash
cd HashLite
```
3. Make build directory
```bash
mkdir build
```
4. open build directory
```bash
cd build
```
5. build library
```bash
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make
```

##### Windows - Visual Studio
1. Clone repository and open directory
```bash
git clone https://github.com/flynn-28/HashLite
```
2. Open Directory
```bash
cd HashLite
```
3. Make build directory
```bash
mkdir build
```
4. open build directory
```bash
cd build
```
5. generate CMake
```bash
cmake .. -G "Visual Studio 16 2019" -A x64
```
6. Build library
Open the generated ``.sln`` file in Visual Studio and build the solution.


## Include Library in Project
1. Add header to project
```cpp
#include <HashLite.h>
```

2. Link Library (Linux/MinGW)
append the following line to your build command:
```bash 
-Iinclude/ -Llib/ -lHashLite
```

3. Link Library (Visual Studio)
   * Add HashLite.lib to the project linker input
   * Add the include/ directory in the projects include paths

-----
## Usage
**1.** Select Algorithm
replace ``{algorithm}`` with desired algorithm
```cpp
    HashLite {algorithm}(HashAlgorithm::{ALGORITHM}); 
```
**2.** Hash data
replace ``{algorithm}`` with desired algorithm
```cpp
sha256.computeHash(data) // change data to the variable you want to hash
```
-------
## Usage Examples

### Hashing Text
```cpp
#include "HashLite.h"
#include <iostream>

int main() {
    std::string input = "Hello, World!"; // define text to be hashed

    HashLite sha256(HashAlgorithm::SHA256); // initialize algorithm (in this case SHA-256)

    std::cout << "Hash: " << sha256.computeHash(input) << std::endl; // hash the text using specified algorithm
}
```

### Hashing a File
```cpp
#include "HashLite.h" 
#include <iostream>
#include <fstream>
#include <sstream>     

int main() {
    std::string filename = "doc.pdf";  // define file
    std::ifstream file(filename, std::ios::binary);  // open file as binary

    std::stringstream buffer;   //  create object to hold string
    buffer << file.rdbuf();     // copy files binary to object
    std::string fileContent = buffer.str();  // convert binary into string

    HashLite crc32(HashAlgorithm::CRC32); // initialize algorithm
    std::cout << crc32.computeHash(fileContent) << std::endl;  // compute and print hash

    file.close(); // close file
    return 0;
}
```
----
## Supported Algorithms
1. [SHA-1](https://en.wikipedia.org/wiki/SHA-1)
2. [SHA-224](https://en.wikipedia.org/wiki/SHA-2)
3. [SHA-256](https://www.simplilearn.com/tutorials/cyber-security-tutorial/sha-256-algorithm)
4. [SHA-384](https://cyberpedia.reasonlabs.com/EN/sha-384.html#:~:text=SHA%2D384%20is%20a%20cryptographic,manipulate%20data%20without%20being%20detected.)
5. [SHA-512](https://komodoplatform.com/en/academy/sha-512/#:~:text=SHA%2D512%2C%20or%20Secure%20Hash,hashing%2C%20and%20digital%20record%20verification.)
6. [MD5](https://en.wikipedia.org/wiki/MD5)
7. [CRC-8](https://imnp.github.io/pygestalt/pages/reference/crc8.html)
8. [CRC-16](https://fastercapital.com/content/All-You-Need-to-Know-About-CRC16--Detecting-Errors-in-Data-Transmission.html)
9. [CRC-32](https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art008)

----
## Notes
- The `computeHash` method must be implemented to perform hashing
- You must initialize every algorithm you plan to use
- Support for more alorithms coming soon, and upon request
----
## Support
For support, create an issue or pull request, or email me at [msmc.dev@gmail.com](mailto:msmc.dev@gmail.com)

