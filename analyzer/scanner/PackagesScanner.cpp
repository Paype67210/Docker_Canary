#include "PackagesScanner.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

namespace fs = std::filesystem;

static bool containsSensitivePackage(const std::string& line, std::string& reason) {
    static const std::vector<std::string> flagged = {
        "telnet", "ftp", "netcat", "gcc", "make", "python2", "perl", "ruby",
        "nmap", "hydra", "socat", "bind", "tcpdump", "strace"
    };

    for (const std::string& pkg : flagged) {
        if (line.find(pkg) != std::string::npos) {
            reason = "Package sensible détecté : " + pkg;
            return true;
        }
    }
    return false;
}

std::vector<PackageInfo> PackagesScanner::scan(const std::string& rootPath) {
    std::vector<PackageInfo> findings;
    std::string reason;

    // Support de APK (Alpine)
    std::string apkPath = rootPath + "/lib/apk/db/installed";
    if (fs::exists(apkPath)) {
        std::ifstream apkFile(apkPath);
        std::string line;
        while (std::getline(apkFile, line)) {
            if (containsSensitivePackage(line, reason)) {
                PackageInfo pkg;
                pkg.name = "📦";
                pkg.version = reason;
                findings.push_back(pkg);
            }
        }
    }

    // Support de DPKG (Debian/Ubuntu)
    std::string dpkgPath = rootPath + "/var/lib/dpkg/status";
    if (fs::exists(dpkgPath)) {
        std::ifstream dpkgFile(dpkgPath);
        std::string line;
        while (std::getline(dpkgFile, line)) {
            if (line.rfind("Package:", 0) == 0) {
                if (containsSensitivePackage(line, reason)) {
                    PackageInfo pkg;
                    pkg.name = "📦 ";
                    pkg.version = reason;
                    
                    findings.push_back(pkg);
                }
            }
        }
    }

    // Support de RPM (RedHat/CentOS)
    std::string rpmDb = rootPath + "/var/lib/rpm/Packages";
    if (fs::exists(rpmDb)) {
        PackageInfo pkg;
        pkg.name = "📦 RPM détecté";
        pkg.version = "Analyse approfondie non supportée (TODO)";
        findings.push_back(pkg);
    }

    if (findings.empty()) {
        PackageInfo pkg;
        pkg.name = "✅";
        pkg.version = "Aucun package sensible trouvé dans l'image.";
        findings.push_back(pkg);
    }

    return findings;
}
