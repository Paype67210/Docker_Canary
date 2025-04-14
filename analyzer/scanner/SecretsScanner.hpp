#ifndef SECRETS_SCANNER_HPP
#define SECRETS_SCANNER_HPP

#include <vector>
#include <string>

struct SecretInfo {
    std::string path;
    std::string line;
    std::string content;
};

class SecretsScanner {
public:
    static std::vector<SecretInfo> scan(const std::string& rootPath);
};

#endif
