# Étape 1 : Build
FROM debian:bookworm AS builder

# Préparer les outils
RUN apt-get update && apt-get install -y \
    build-essential \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copier le code source
COPY report/ report/
COPY scanner/ scanner/
COPY utils/ utils/
COPY test/test_docker_canary.cpp test/
COPY main.cpp .
COPY Makefile .

# Compiler le projet
RUN make

# Étape 2 : Image finale, plus légère
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    tar \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /canary

# Copier le binaire depuis l’étape de build
COPY --from=builder /app/analyzer ./analyzer

# Point d’entrée par défaut
ENTRYPOINT ["./analyzer"]
