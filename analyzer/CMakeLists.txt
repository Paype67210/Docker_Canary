cmake_minimum_required(VERSION 3.14)
project(DockerCanary)

set(CMAKE_CXX_STANDARD 20)

include_directories(analyzer scanner utils)

add_executable(DockerCanary
    test/test_docker_canary.cpp
    scanner/TarExtractor.cpp
    scanner/SecretsScanner.cpp
    scanner/BinariesScanner.cpp
    scanner/PackagesScanner.cpp
    report/ReportBuilder.cpp
)
