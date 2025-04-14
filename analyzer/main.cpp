#include <iostream>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>

#include "scanner/SecretsScanner.hpp"
#include "scanner/BinariesScanner.hpp"
#include "scanner/PackagesScanner.hpp"
#include "scanner/LargeFilesScanner.hpp"
#include "utils/TarExtractor.hpp"
#include "report/ReportBuilder.hpp"

// Fonction pour afficher un spinner dynamique
void showSpinner(std::atomic<bool>& running) {
    const char spinner[] = {'|', '/', '-', '\\'};
    int index = 0;
    while (running) {
        std::cout << "\r🔎 Analyse en cours... " << spinner[index] << std::flush;
        index = (index + 1) % 4;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::cout << "\r🔎 Analyse terminée.          \n"; // Efface le spinner
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <docker-image.tar>\n";
        return 1;
    }

    std::string imagePath = argv[1];
    std::string extractDir = "/tmp/docker_canary_extract";

    // Extraire l'image Docker
    std::cout << "🗂️ Extraction de l'image: " << imagePath << std::endl;
    if (!TarExtractor::extract(imagePath, extractDir)) {
        std::cerr << "❌ Erreur d'extraction\n";
        return 2;
    }
    std::cout << "✅ Image extraite dans: " << extractDir << std::endl;

    // Lancer le spinner dans un thread séparé
    std::atomic<bool> running(true);
    std::thread spinnerThread(showSpinner, std::ref(running));

    // Lancer les analyses
    std::cout << "🔍 Analyse des secrets...\n";
    auto secrets = SecretsScanner::scan(extractDir);
    std::cout << "🔍 Analyse des binaires...\n";
    auto binaries = BinariesScanner::scan(extractDir);
    std::cout << "🔍 Analyse des packages...\n";
    auto packages = PackagesScanner::scan(extractDir);
    std::cout << "🔍 Analyse des fichiers volumineux...\n";
    auto largeFiles = LargeFilesScanner::scan(extractDir);

    // Arrêter le spinner
    running = false;
    if (spinnerThread.joinable()) {
        spinnerThread.join();
    }
    std::cout << "✅ Extraction et analyse terminées.\n";

    auto builder = ReportBuilder::fromScanners(secrets, binaries, packages, largeFiles);
    std::cout << builder.toJson(4) << std::endl;

    return 0;
}
