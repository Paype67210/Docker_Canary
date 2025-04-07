#ifndef SECRETS_SCANNER_HPP
#define SECRETS_SCANNER_HPP

#include <vector>
#include <string>

class SecretsScanner {
public:
    static std::vector<std::string> scan(const std::string& rootPath);
};

#endif
