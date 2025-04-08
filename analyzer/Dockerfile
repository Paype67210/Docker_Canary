# Étape 1 : Build
FROM debian:bookworm as builder

# Préparer les outils
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copier le code source
COPY main.cpp analyzer/
COPY ./analyzer/* analyzer/
COPY ./analyzer/report/* report/
COPY ./analyzer/utils/* utils/
COPY ./analyzer/test/* test/

# Créer un CMakeLists.txt à la volée si besoin
COPY CMakeLists.txt .

# Compiler le projet
RUN cmake . && make

# Étape 2 : Image finale, plus légère
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    tar \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /canary

# Copier le binaire depuis l’étape de build
COPY --from=builder /app/DockerCanary ./DockerCanary

# Point d’entrée par défaut
ENTRYPOINT ["./DockerCanary"]
