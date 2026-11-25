# IDA BugFix

Outil web indépendant d'analyse statique de dépôts GitHub publics et d'audit de sites web.

## Mode 1 — Dépôt GitHub
- Analyse de dépôts publics via l'API GitHub.
- Inspection limitée à 60 fichiers texte de 150 Ko maximum.
- Recherche de motifs suspects : secrets, eval(), innerHTML, traces console, TODO/FIXME et URL localhost.
- Vérification de syntaxe JSON et export d'un rapport JSON.
- Aucun code distant exécuté, aucun fichier distant modifié.

## Mode 2 — Site web
- Audit d'une URL publique via Google PageSpeed Insights / Lighthouse.
- Scores Performance, Accessibilité, Bonnes pratiques et SEO.
- Indicateurs de chargement et diagnostics à examiner.
- Choix mobile ou ordinateur et export du rapport JSON.
- Une clé API Google peut être nécessaire selon les quotas. La clé saisie reste dans la page et n'est pas enregistrée par IDA BugFix.

## Limites et sécurité
L'analyse GitHub est heuristique et ne remplace pas les tests ou une revue humaine. L'audit web dépend de Google PageSpeed Insights et de l'accessibilité du site. Les scores varient selon le réseau, l'appareil et le moment. Aucun site ni dépôt n'est modifié. L'URL du site est transmise à Google PageSpeed Insights pour réaliser le test.

## Lancement
Ouvrir index.html ou publier le dépôt avec GitHub Pages.
