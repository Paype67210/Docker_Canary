#include "../utils/TarExtractor.hpp"
#include "../scanner/SecretsScanner.hpp"
#include "../scanner/BinariesScanner.hpp"
#include "../report/ReportBuilder.hpp"
#include "../scanner/PackagesScanner.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <image.tar>\n";
        return 1;
    }

    const std::string tarPath = argv[1];
    const std::string extractDir = "/tmp/docker_canary_extract";

    if (!TarExtractor::extract(tarPath, extractDir)) {
        std::cerr << "Extraction échouée.\n";
        return 1;
    }

    ReportBuilder report;

    auto secrets = SecretsScanner::scan(extractDir);
    report.addSection("Secrets", secrets);

    auto binaries = BinariesScanner::scan(extractDir);
    report.addSection("Binaries", binaries);

    auto packages = PackagesScanner::scan(extractDir);
    report.addSection("Packages", packages);

    std::cout << report.toJson(2) << "\n";

    return 0;
}
