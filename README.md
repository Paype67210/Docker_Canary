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
```
## 📁 Structure du projet

```bash
analyzer/     -> Outils d’analyse Docker
api/          -> Backend Fastify
frontend/     -> Interface web (SPA)
badge/        -> Générateur de badge SVG
storage/      -> Stockage des rapports (SQLite)
```

## 🧱 Feuille de route (Roadmap MVP)

- [ ] Module analyzer/ : parseur de .tar (docker save)

- [ ] API REST simple pour envoyer une image

- [ ] Interface de visualisation (SPA)

- [ ] Générateur de badge SVG

- [ ] Déploiement de la version alpha

## 🧠 Inspirations
<ul data-start="2582" data-end="2737">
<li data-start="2582" data-end="2630" class="" style="">
<p data-start="2584" data-end="2630" class=""><a data-start="2584" data-end="2630" rel="noopener" target="_new" class="" href="https://github.com/aquasecurity/trivy">Trivy</a></p>
</li>
<li data-start="2631" data-end="2681" class="" style="">
<p data-start="2633" data-end="2681" class=""><a data-start="2633" data-end="2681" rel="noopener" target="_new" class="" href="https://github.com/goodwithtech/dockle">Dockle</a></p>
</li>
<li data-start="2682" data-end="2737" class="" style="">
<p data-start="2684" data-end="2737" class=""><a data-start="2684" data-end="2717" rel="noopener" target="_new" class="" href="https://shields.io/">shields.io</a> pour les badges SVG</p>
</li>
</ul>

## 📄 Licence

MIT – libre pour usage personnel et pro.
