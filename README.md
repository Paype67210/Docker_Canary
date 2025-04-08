# 🚦 Docker Canary

**Docker Canary** est un scanner intelligent d’images Docker. Il détecte les vulnérabilités, binaires suspects, fichiers sensibles et packages inutiles, tout en proposant des recommandations pour réduire la taille de vos images.

## 🎯 Objectif

Faciliter l’analyse rapide et lisible de vos images Docker pour améliorer :
- La sécurité
- La légèreté
- Les bonnes pratiques DevOps

## 🧰 Fonctionnalités prévues (MVP)

- [x] Upload ou analyse d’une image Docker (`docker save`)
- [x] Rapport lisible avec score de sécurité
- [x] Détection :
  - fichiers secrets oubliés (`.env`, `.ssh/`, etc.)
  - binaires inconnus ou suspects
  - packages inutiles
- [x] Suggestions de réduction de taille
- [ ] Générateur de badge à intégrer dans le README
- [ ] API REST pour automatiser les analyses

## 🧪 Stack technique

| Côté | Technologie |
|------|-------------|
| Backend API | Fastify (TypeScript) |
| Analyse image | C++ / Shell / Node |
| Frontend | SPA (React ou Preact) |
| Base de données | SQLite |
| Reverse proxy | Nginx |
| Containerisation | Docker + docker-compose |

## 🔧 Démarrage rapide

```bash
git clone https://github.com/Paype67210/docker-Canary.git
cd dockerCanary
cp .env.example .env
docker-compose up --build
