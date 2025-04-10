#include "ReportBuilder.hpp"
#include <sstream>

void ReportBuilder::addSection(const std::string& name, const std::vector<std::string>& findings) {
    sections[name] = findings;
}

std::string ReportBuilder::toJson(int indent) const {
    std::ostringstream oss;
    std::string ind(indent, ' ');

    oss << "{\n";
    oss << ind << "\"score\": " << computeGlobalScore() << ",\n";
    oss << ind << "\"sections\": {\n";

    for (auto it = sections.begin(); it != sections.end(); ++it) {
        oss << ind << ind << "\"" << it->first << "\": [\n";
        for (size_t i = 0; i < it->second.size(); ++i) {
            oss << ind << ind << ind << "\"" << it->second[i] << "\"";
            if (i + 1 < it->second.size()) oss << ",";
            oss << "\n";
        }
        oss << ind << ind << "]";
        if (std::next(it) != sections.end()) oss << ",";
        oss << "\n";
    }

    oss << ind << "}\n";
    oss << "}";
    return oss.str();
}

int ReportBuilder::computeGlobalScore() const {
    int totalIssues = 0;
    for (const auto& [_, findings] : sections)
        totalIssues += findings.size();

    if (totalIssues == 0) return 100;
    if (totalIssues < 3) return 90;
    if (totalIssues < 6) return 70;
    if (totalIssues < 10) return 50;
    return 20;
}

// ReportBuilder ReportBuilder::fromScanners(const std::vector<SecretInfo>& secrets,
//     const std::vector<BinaryInfo>& binaries,
//     const std::vector<PackageInfo>& packages,
//     const std::vector<LargeFileInfo>& largeFiles)
// {
//     ReportBuilder builder;

//     std::vector<std::string> secretFindings;
//     for (const auto& s : secrets) {
//     secretFindings.push_back(s.path + ":" + std::to_string(s.line) + " => " + s.content);
//     }
//     builder.addSection("Secrets", secretFindings);

//     std::vector<std::string> binaryFindings;
//     for (const auto& b : binaries) {
//     binaryFindings.push_back(b.path + " (arch: " + b.architecture + ", stripped: " + (b.isStripped ? "yes" : "no") + ")");
//     }
//     builder.addSection("Suspicious Binaries", binaryFindings);

//     std::vector<std::string> packageFindings;
//     for (const auto& p : packages) {
//     packageFindings.push_back(p.name + " - " + p.version);
//     }
//     builder.addSection("Packages", packageFindings);

//     std::vector<std::string> largeFileFindings;
//     for (const auto& f : largeFiles) {
//     largeFileFindings.push_back(f.path + " (" + std::to_string(f.size) + " bytes)");
//     }
//     builder.addSection("Large Files", largeFileFindings);

//     return builder;
// }
