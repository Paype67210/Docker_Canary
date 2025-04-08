#include "ReportBuilder.hpp"
#include <sstream>
#include <iomanip>

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
