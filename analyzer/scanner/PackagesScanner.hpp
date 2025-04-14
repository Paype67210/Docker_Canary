#ifndef PACKAGES_SCANNER_HPP
#define PACKAGES_SCANNER_HPP

#include <string>
#include <vector>

struct PackageInfo {
    std::string name;
    std::string version;
};

class PackagesScanner {
public:
    static std::vector<PackageInfo> scan(const std::string& rootPath);
};

#endif
