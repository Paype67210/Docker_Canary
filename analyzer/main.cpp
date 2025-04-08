#include <iostream>
#include <string>
#include <filesystem>

#include "./scanner/SecretsScanner.hpp"
#include "./scanner/BinariesScanner.hpp"
#include "./scanner/LargeFilesScanner.hpp"
#include "utils/TarExtractor.hpp"
#include "./utils/ReportBuilder.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <docker-image.tar>\n";
        return 1;
    }

    std::string imagePath = argv[1];
    std::string extractDir = "/tmp/docker_canary_extract";

    std::cout << "🗂️ Extraction de l'image: " << imagePath << std::endl;
    if (!TarExtractor::extract(imagePath, extractDir)) {
        std::cerr << "❌ Erreur d'extraction\n";
        return 2;
    }

    std::cout << "🔎 Analyse en cours...\n";
    auto secrets = SecretsScanner::scan(extractDir);
    auto bins = BinariesScanner::scan(extractDir);
    auto largeFiles = LargeFilesScanner::scan(extractDir);

    std::cout << "🧾 Génération du rapport JSON\n";
    auto report = ReportBuilder::build(secrets, bins, largeFiles);
    std::cout << report.dump(4) << std::endl;

    return 0;
}
