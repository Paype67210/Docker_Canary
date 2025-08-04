#include "SecretsScanner.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <vector>
#include <sstream>

namespace fs = std::filesystem;

// Fichiers et dossiers à ignorer lors du scan
static const std::set<std::string> excludeDirs = {
    ".git", "node_modules", "venv", "__pycache__", "dist", "build"
};

static const std::vector<std::string> suspiciousFilenames = {
    ".env", "id_rsa", "id_dsa", "credentials.json", ".htpasswd",
    "config.json", "docker-compose.override.yml", "secrets.yml",
    "private.key", "jwt.key", "aws_credentials", ".nprmc", ".pypirc",
    "settings.py"
};

// Patterns de contenus pour détecter des secrets courants
static const std::vector<std::regex> suspiciousPatterns = {
    // AWS
    std::regex(R"(AWS_SECRET_ACCESS_KEY\s*=\s*\S+)", std::regex::icase),
    std::regex(R"(AKIA[0-9A-Z]{16})"), // AWS Access Key
    std::regex(R"(aws_access_key_id\s*=\s*\S+)", std::regex::icase),
    std::regex(R"(aws_secret_access_key\s*=\s*\S+)", std::regex::icase),

    // GitHub tokens
    std::regex(R"(ghp_[A-Za-z0-9]{36,255})"),
    std::regex(R"(gho_[A-Za-z0-9]{36,255})"),
    std::regex(R"(github_pat_[A-Za-z0-9_]{22,255})"),

    // Slack tokens
    std::regex(R"(xox[baprs]-[A-Za-z0-9-]{10,48})"),

    // JWT
    std::regex(R"([A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})"),

    // Private key, generic secrets
    std::regex(R"(-----BEGIN\s+PRIVATE\s+KEY-----)", std::regex::icase),
    std::regex(R"(-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----)", std::regex::icase),
    std::regex(R"(-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----)", std::regex::icase),
    std::regex(R"(-----BEGIN\s+EC\s+PRIVATE\s+KEY-----)", std::regex::icase),

    // Generic credentials
    std::regex(R"(password\s*[:=]\s*['"]?[^'"\s]+['"]?)", std::regex::icase),
    std::regex(R"(api[_-]?key\s*[:=]\s*['"]?[^'"\s]+['"]?)", std::regex::icase),
    std::regex(R"(secret\s*[:=]\s*['"]?[^'"\s]+['"]?)", std::regex::icase),
    std::regex(R"(client[_-]?secret\s*[:=]\s*['"]?[^'"\s]+['"]?)", std::regex::icase),
    std::regex(R"(authorization\s*[:=]\s*['"]?[^'"\s]+['"]?)", std::regex::icase)
};

// Vérifie si un fichier est probablement binaire
bool isBinary(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    char c;
    int count = 0;
    while (file.get(c) && count < 1024) {
        if (static_cast<unsigned char>(c) == 0) return true;
        ++count;
    }
    return false;
}

// Vérifie si le chemin doit être exclu du scan
bool isExcluded(const fs::path& path) {
    for (const auto& part : path) {
        if (excludedDirs.count(part.string()) > 0) return true;
    }
    return false;
}

std::vector<SecretInfo> SecretsScanner::scan(const std::string& rootPath) {
    std::vector<SecretInfo> results;

    for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (entry.status().type() != fs::file_type::regular)
            continue;
        if (isExcluded(entry.path()))
            continue;

        std::string path = entry.path().string();
        std::string filename = entry.path().filename().string();

        // Ignore les fichiers binaires ou trop gros (>5Mo ici)
        if (isBinary(path) || fs::file_size(entry.path()) > 5 * 1024 * 1024)
            continue;
        
        // Détection par nom de fichier exact
        for (const auto& suspiciousName : suspiciousFilenames) {
            if (filename == suspiciousName) {
                SecretInfo info;
                info.line = "🕵️ Nom de fichier suspect";
                info.path = path;
                info.content = "Fichier trouvé : " + filename;
                results.push_back(info);
                break;
            }
        }

        // Détection par regex sur le nom de fichier
        for (const auto& pattern : suspiciousFilenamePatterns) {
            if (std::regex_search(filename, pattern)) {
                SecretInfo info;
                info.line = "🕵️ Pattern suspect sur le nom";
                info.path = path;
                info.content = "Fichier trouvé (pattern) : " + filename;
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
        std::vector<std::string> contextLines;
        while (std::getline(file, line)) {
            ++lineNum;
            // On garde 2 lignes autour pour le contexte
            contextLines.push_back(line);
            if (contextLines.size() > 5) // garder une petite fenêtre
                contextLines.erase(contextLines.begin());

            for (const auto& pattern : suspiciousPatterns) {
                std::smatch match;
                if (std::regex_search(line, match, pattern)) {
                    SecretInfo info;
                    info.line = "🔐 Motif suspect";
                    info.path = path;
                    info.content = "Ligne " + std::to_string(lineNum) + ": " + line;
                    
                    // Ajoute le contexte autour de la ligne trouvée
                    std::ostringstream oss;
                    int start = std::max(0, (int)contextLines.size() - 3);
                    for (int i = start; i < (int)contextLines.size(); ++i)
                        oss << contextLines[i] << "\n";
                    info.content += "\nContexte:\n" + oss.str();

                    results.push_back(info);
                    break;
                }
            }
        }
    }

    return results;
}
