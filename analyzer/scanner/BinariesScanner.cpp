#include "BinariesScanner.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

static bool isStripped(const std::string& binaryPath) {
    // Commande pour vérifier la présence de la section .symtab
    std::string command = "readelf -S " + binaryPath + " | grep .symtab > /dev/null 2>&1";
    int result = std::system(command.c_str());

    // Si le résultat est 0, .symtab existe, donc le fichier n'est pas stripped
    return result != 0; // Retourne true si le fichier est stripped
}

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

std::vector<BinariesInfos> BinariesScanner::scan(const std::string& rootPath) {
    std::vector<BinariesInfos> results;

    for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (entry.status().type() != fs::file_type::regular)
            continue;

        fs::path filePath = entry.path();
        if (!isExecutable(filePath))
            continue;

        if (isELF(filePath)) {
            BinariesInfos info;
            info.architecture = "⚙️ ELF détecté";
            info.path = filePath.string();
            info.isStripped = isStripped(filePath.string());
            results.push_back(info);
        } else if (hasSuspiciousShebang(filePath)) {
            BinariesInfos info;
            info.architecture = "📜 Script exécutable détecté";
            info.path = filePath.string();
            info.isStripped = false; // Les scripts ne sont pas "stripped" au sens ELF
            results.push_back(info);
        } else {
            BinariesInfos info;
            info.architecture = "❓ Exécutable non identifié";
            info.path = filePath.string();
            info.isStripped = isStripped(filePath.string());
            results.push_back(info);
        }
    }

    return results;
}
