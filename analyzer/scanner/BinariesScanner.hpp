#ifndef BINARIES_SCANNER_HPP
#define BINARIES_SCANNER_HPP

#include <vector>
#include <string>

struct BinariesInfos {
    std::string path;
    std::string architecture;
    bool isStripped;
};

class BinariesScanner {
public:
    static std::vector<BinariesInfos> scan(const std::string& rootPath);
};

#endif
