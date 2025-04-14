#include "LargeFilesScanner.hpp"
#include <iostream>
#include <filesystem>


namespace fs = std::filesystem;

uintmax_t LargeFilesScanner::getSizeThreshold() const {
	return sizeThreshold;
}

LargeFilesScanner::LargeFilesScanner(const std::string& directory, uintmax_t sizeThresholdBytes)
    : directoryPath(directory), sizeThreshold(sizeThresholdBytes) {}

std::vector<LargeFileInfo> LargeFilesScanner::scan(const std::string& rootPath) {
    LargeFilesScanner scanner(rootPath);
	std::vector<LargeFileInfo> results;
    for (auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (entry.status().type() != fs::file_type::regular)
            continue;

        try {
            auto size = fs::file_size(entry);
            if (size >= scanner.getSizeThreshold()) {
                LargeFileInfo info;
				info.path = entry.path().string();
				info.size = size;
				results.push_back(info);
        }
        } catch (const std::exception& e) {
            std::cerr << "Error reading file: " << entry.path() << " (" << e.what() << ")\n";
        }
    }

    return results;
}
