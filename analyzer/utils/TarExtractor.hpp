#ifndef TAREXTRACTOR_HPP
#define TAREXTRACTOR_HPP

#include <string>

class TarExtractor {
public:
    static bool extract(const std::string& tarPath, const std::string& outputDir);
};

#endif
