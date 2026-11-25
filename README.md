# IDA BugFix 2.1.0

Plateforme web de diagnostic : dépôts GitHub publics, projets ZIP locaux et audits web via Google PageSpeed Insights / Lighthouse.

## Nouveautés 2.1.0 — Analyse de projets ZIP
- Import d’une archive ZIP depuis mobile ou ordinateur.
- Analyse directement dans le navigateur : les fichiers ne sont pas téléversés.
- Inspection statique de JavaScript, TypeScript, JSON, HTML, CSS, Python, PHP, Java, Go, Rust, SQL, YAML, TOML, Markdown, XML, Vue et Svelte.
- Détection heuristique de secrets potentiels, eval(), innerHTML, traces console, TODO/FIXME, URLs localhost, JSON invalide et gestion fetch à vérifier.
- Rapport JSON exportable avec gravité, emplacement, résumé et recommandations.
- Limites : ZIP 30 Mo, 300 fichiers candidats, 1 Mo par fichier, 25 Mo de texte traité.
- Exclusion des dossiers de dépendances et de compilation courants.

## Modes existants
### GitHub public
- Inspection limitée à 60 fichiers texte de 150 Ko maximum.
- Aucun code distant exécuté et aucun fichier distant modifié.
### Audit web
- Google PageSpeed Insights / Lighthouse : performances, accessibilité, bonnes pratiques et SEO.
- Le site doit être public. Une clé API Google peut être nécessaire selon les quotas.
- L’URL du site est transmise à Google PageSpeed Insights.

## Limites et sécurité
La version 2.1.0 est un outil de diagnostic statique. Elle ne comprend pas toutes les erreurs possibles, ne modifie pas le code, n’exécute pas les tests et ne garantit pas l’absence de bugs. Les alertes sont des pistes à vérifier. Le mode ZIP utilise JSZip chargé depuis jsDelivr ; une connexion est nécessaire pour charger cette bibliothèque. Les fichiers de l’archive restent dans le navigateur pendant l’analyse.

## Utilisation
Ouvrir l’application, choisir GitHub, Projet ZIP ou Audit web, puis lancer l’analyse.
## Nouveautés 2.1.0 — Espace Pro
- Historique local des 20 derniers diagnostics GitHub, ZIP et audits web.
- Recherche textuelle et filtres par niveau de gravité dans les résultats.
- Rapport professionnel imprimable depuis le navigateur (option « Enregistrer en PDF »).
- Export JSON individuel et export de l'historique.
- L'historique est stocké uniquement dans le navigateur de l'utilisateur et ne se synchronise pas entre appareils.
- Aucun compte, serveur, paiement ou synchronisation cloud n'est inclus dans cette version.
