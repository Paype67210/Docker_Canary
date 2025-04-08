#ifndef BINARIES_SCANNER_HPP
#define BINARIES_SCANNER_HPP

#include <vector>
#include <string>

class BinariesScanner {
public:
    static std::vector<std::string> scan(const std::string& rootPath);
};

#endif
