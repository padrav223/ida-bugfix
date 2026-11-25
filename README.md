# IDA BugFix

Outil web indépendant de diagnostic statique de dépôts GitHub publics, en français et adapté au mobile.

## Fonctionnement actuel

- Récupère les métadonnées et l'arborescence d'un dépôt public via l'API GitHub.
- Inspecte jusqu'à 60 fichiers texte de 150 Ko maximum, en donnant la priorité aux fichiers `.env` (hors modèles d'exemple) et à `package.json`.
- Recherche certains motifs : secrets potentiellement exposés, `eval()`, `innerHTML`, traces console, TODO/FIXME et URL localhost.
- Vérifie la syntaxe des fichiers JSON.
- Exporte un rapport JSON.
- N'exécute aucun code du dépôt et ne modifie aucun fichier distant.

## Limites importantes

C'est une première analyse statique heuristique, pas un moteur IA ni un remplacement de tests, ESLint, TypeScript ou d'une revue humaine. Les résultats peuvent contenir des faux positifs et ne garantissent pas l'absence de bugs. Les dépôts privés, les gros dépôts et les analyses complètes ne sont pas pris en charge.

## Sécurité

Le code du dépôt est traité comme une donnée non fiable. Aucun token, mot de passe ou clé API n'est demandé. L'analyse s'effectue depuis le navigateur et n'exécute pas le code inspecté.

## Lancement

Ouvrir `index.html` ou publier le dépôt avec GitHub Pages.
