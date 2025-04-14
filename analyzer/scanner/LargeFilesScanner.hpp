#ifndef LARGEFILESSCANNER_HPP
#define LARGEFILESSCANNER_HPP

#include <string>
#include <vector>
#include <filesystem>

struct LargeFileInfo {
    std::string path;
    uintmax_t size;
};

class LargeFilesScanner {
public:
    LargeFilesScanner(const std::string& directory, uintmax_t sizeThresholdBytes = 10 * 1024 * 1024); // 10 MB par défaut
	static std::vector<LargeFileInfo> scan(const std::string& rootPath);
	uintmax_t getSizeThreshold() const;
	
private:
    std::string directoryPath;
    uintmax_t sizeThreshold;
};

#endif // LARGEFILESSCANNER_HPP
