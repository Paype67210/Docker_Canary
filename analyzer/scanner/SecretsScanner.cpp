#include "SecretsScanner.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>

namespace fs = std::filesystem;

static const std::vector<std::string> suspiciousFilenames = {
    ".env", "id_rsa", "id_dsa", "credentials.json", ".htpasswd",
    "config.json", "docker-compose.override.yml", "secrets.yml",
    "private.key", "jwt.key", "aws_credentials"
};

static const std::vector<std::regex> suspiciousPatterns = {
    std::regex(R"(AWS_SECRET_ACCESS_KEY\s*=\s*\S+)", std::regex::icase),
    std::regex(R"(password\s*=\s*\S+)", std::regex::icase),
    std::regex(R"(-----BEGIN\s+PRIVATE\s+KEY-----)", std::regex::icase),
    std::regex(R"(api[_-]?key\s*[:=]\s*\S+)", std::regex::icase),
    std::regex(R"(secret\s*[:=]\s*\S+)", std::regex::icase)
};

std::vector<SecretInfo> SecretsScanner::scan(const std::string& rootPath) {
    std::vector<SecretInfo> results;

    for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (entry.status().type() != fs::file_type::regular)
            continue;

        std::string path = entry.path().string();
        std::string filename = entry.path().filename().string();

        // Détection par nom de fichier
        for (const auto& suspiciousName : suspiciousFilenames) {
            if (filename == suspiciousName) {
                SecretInfo info;
                info.line = "🕵️ Nom suspect";
                info.path = path;
                info.content = "Fichier trouvé : " + filename;
                results.push_back(info);
                break;
            }
        }

        // Détection par contenu
        std::ifstream file(path);
        if (!file)
            continue;

        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            ++lineNum;
            for (const auto& pattern : suspiciousPatterns) {
                if (std::regex_search(line, pattern)) {
                    SecretInfo info;
                    info.line = "🔐 Motif suspect";
                    info.path = path;
                    info.content = " (ligne " + std::to_string(lineNum) + ")";
                    results.push_back(info);
                    break;
                }
            }
        }
    }

    return results;
}
