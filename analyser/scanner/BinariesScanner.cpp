#include "BinariesScanner.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

static bool isExecutable(const fs::path& path) {
    struct stat fileStat;
    return stat(path.c_str(), &fileStat) == 0 && (fileStat.st_mode & S_IXUSR);
}

static bool isELF(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    unsigned char magic[4];
    f.read(reinterpret_cast<char*>(magic), 4);
    return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

static bool hasSuspiciousShebang(const fs::path& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::string firstLine;
    std::getline(f, firstLine);
    return firstLine.rfind("#!", 0) == 0 &&
           (firstLine.find("bash") != std::string::npos || firstLine.find("python") != std::string::npos || firstLine.find("sh") != std::string::npos);
}

std::vector<std::string> BinariesScanner::scan(const std::string& rootPath) {
    std::vector<std::string> results;

    for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (!entry.is_regular_file())
            continue;

        fs::path filePath = entry.path();
        if (!isExecutable(filePath))
            continue;

        if (isELF(filePath)) {
            results.push_back("⚙️ ELF détecté : " + filePath.string());
        } else if (hasSuspiciousShebang(filePath)) {
            results.push_back("📜 Script exécutable : " + filePath.string());
        } else {
            results.push_back("❓ Exécutable non identifié : " + filePath.string());
        }
    }

    return results;
}
