#include "TarExtractor.hpp"
#include <iostream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

bool TarExtractor::extract(const std::string& tarPath, const std::string& outputDir) {
    // Vérifie que le fichier .tar existe
    if (!fs::exists(tarPath)) {
        std::cerr << "❌ Le fichier " << tarPath << " n'existe pas.\n";
        return false;
    }

    // Crée le dossier d'extraction s'il n'existe pas
    if (!fs::exists(outputDir)) {
        fs::create_directories(outputDir);
    }

    // Construit la commande system tar
    std::string command = "tar -xf \"" + tarPath + "\" -C \"" + outputDir + "\"";
    int result = std::system(command.c_str());

    if (result != 0) {
        std::cerr << "❌ Échec de l'extraction de l'image avec la commande : " << command << "\n";
        return false;
    }

    return true;
}
