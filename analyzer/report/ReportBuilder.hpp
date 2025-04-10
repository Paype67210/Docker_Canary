#ifndef REPORT_BUILDER_HPP
#define REPORT_BUILDER_HPP

#include <string>
#include <map>
#include <vector>

#include "../scanner/SecretsScanner.hpp"
#include "../scanner/BinariesScanner.hpp"
#include "../scanner/PackagesScanner.hpp"
// #include "../scanner/LargeFileScanner.hpp"

class ReportBuilder {
public:
    void addSection(const std::string& name, const std::vector<std::string>& findings);
    std::string toJson(int indent = 4) const;
    int computeGlobalScore() const; // 100 = safe, 0 = critical

    // static ReportBuilder fromScanners(const std::vector<SecretInfo>& secrets,
    //                                   const std::vector<BinaryInfo>& binaries,
    //                                   const std::vector<PackageInfo>& packages,
    //                                   const std::vector<LargeFileInfo>& largeFiles);
private:
    std::map<std::string, std::vector<std::string>> sections;
};

#endif
