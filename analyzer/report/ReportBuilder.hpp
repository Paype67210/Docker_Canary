#ifndef REPORT_BUILDER_HPP
#define REPORT_BUILDER_HPP

#include <string>
#include <map>
#include <vector>

class ReportBuilder {
public:
    void addSection(const std::string& name, const std::vector<std::string>& findings);
    std::string toJson(int indent = 2) const;
    int computeGlobalScore() const; // 100 = safe, 0 = critical

private:
    std::map<std::string, std::vector<std::string>> sections;
};

#endif
