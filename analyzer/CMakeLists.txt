cmake_minimum_required(VERSION 3.10)
project(DockerCanary)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set the build type
target_link_libraries(DockerCanary PRIVATE stdc++fs)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3 -Wall -Wextra -Werror -std=c++17")

# Add the include directories
add_executable(DockerCanary
	./main.cpp
	/analyzer/scanner/BinariesScanner.cpp
	/analyzer/scanner/PackagesScanner.cpp
	/analyzer/scanner/SecretsScanner.cpp
	/analyzer/scanner/LargeFilesScqanner.cpp
	/analyzer/test/test_docker_canary.cpp
	/analyzer/utils/TarExtractor.cpp
	/analyzer/report/ReportBuilder.cpp
	)
