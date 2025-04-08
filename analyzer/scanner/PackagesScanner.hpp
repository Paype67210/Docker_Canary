#ifndef PACKAGES_SCANNER_HPP
#define PACKAGES_SCANNER_HPP

#include <string>
#include <vector>

class PackagesScanner {
public:
    static std::vector<std::string> scan(const std::string& rootPath);
};

#endif
