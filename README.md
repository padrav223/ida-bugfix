# IDA BugFix 2.4.0 — moteur de diagnostic renforcé

IDA BugFix propose trois entrées de diagnostic : dépôts GitHub publics, archives ZIP locales et audits de sites via Google PageSpeed Insights / Lighthouse.

## Fonctions disponibles dans l'application
- Analyse statique GitHub (jusqu'à 60 fichiers texte) et détection de secrets à motifs connus.
- Audit de dépendances épinglées via OSV.dev : npm (`package-lock.json`), Python (`requirements*.txt`), Go (`go.mod`), Rust (`Cargo.lock`) et PHP (`composer.lock`).
- Les requêtes OSV transmettent uniquement les noms, écosystèmes et versions des dépendances ; le code source n'est pas envoyé à OSV.
- Analyse ZIP locale dans le navigateur avec précontrôle des tailles décompressées, plafond global, limite par fichier et détection de ratios de compression anormaux.
- Audit web Lighthouse via PageSpeed Insights.
- Historique local des 20 derniers rapports, filtres, export JSON, rapports imprimables et export standard SARIF 2.1.0 pour les constats GitHub et ZIP.
- Plan de correction priorisé à partir des alertes : recommandations et étapes de vérification, sans modification automatique du code.

## Fondations SaaS ajoutées en 2.2.0
- Interface de création de compte et de connexion par e-mail avec Supabase Auth.
- Synchronisation des rapports vers une base Supabase après configuration et authentification.
- Tableau de bord client avec identité, formule et nombre de rapports synchronisés.
- Schéma SQL pour profils, rapports et licences, avec Row Level Security et politiques d'accès par propriétaire.
- Structure d'offres Free, Pro et Team et statut de licence administrable côté serveur.
- Zone explicative réservée à l'exécution isolée des tests.

## Moteur sécurité 2.4.0

L'analyse AST suit certaines données non fiables dans le code JavaScript, mais sa propagation est limitée et peut produire des faux positifs ou manquer des chemins complexes. Elle ne prouve pas qu'une faille est exploitable. Les fichiers TypeScript, JSX et TSX ne sont pas analysés par l'AST Acorn dans cette version. L'audit OSV couvre uniquement les formats de verrouillage et versions reconnus ; il ne remplace pas un audit complet des dépendances. Si OSV.dev est inaccessible, le rapport signale que la vérification est incomplète au lieu de prétendre qu'aucune vulnérabilité n'existe.

L'analyse ZIP vérifie les tailles décompressées déclarées par l'archive avant de lire les fichiers et refuse les entrées dépassant les limites configurées.

## Activation cloud
Le projet Supabase dédié à IDA BugFix et son schéma SQL sont déjà configurés. Ne créez pas un second projet et ne remplacez pas ces identifiants sans raison.

1. Ouvrir la [configuration Auth du projet IDA BugFix](https://supabase.com/dashboard/project/jahqximmxhycoslprifl/auth/url-configuration).
2. Définir **Site URL** et ajouter comme URL de redirection autorisée : `https://padrav223.github.io/ida-bugfix/`.
3. Ouvrir IDA BugFix, conserver l'URL et la clé publique préremplies, puis créer un compte.
4. Confirmer l'adresse e-mail si Supabase le demande, puis se connecter. Les nouveaux rapports locaux seront synchronisés après connexion.
5. Pour attribuer une formule Pro/Team, l'administrateur doit mettre à jour la licence depuis un environnement serveur protégé.

La configuration reste dans le navigateur. Ne jamais utiliser une clé `service_role` ou une clé secrète dans le navigateur.

## Ce qui n'est pas encore activé
- Le projet Supabase dédié IDA BugFix est préconfiguré dans l'application. Aucun compte cloud n'est créé automatiquement.
- Vérifier dans Supabase que l'URL Site URL et l'URL de redirection autorisée correspondent à `https://padrav223.github.io/ida-bugfix/` avant le premier test d'inscription.
- Aucun prestataire de paiement (Stripe, PayDunya, etc.) ni webhook de paiement n'est raccordé : les offres affichées ne déclenchent aucun prélèvement.
- Aucun moteur n'exécute le code client. L'exécution de code non fiable exige un service sandbox isolé, avec quotas, réseau restreint, limites de ressources et suppression des environnements.
- Les corrections sont des recommandations, pas des patchs automatiques ni des garanties de résolution.
- Les rôles d'administration et l'attribution des licences doivent être effectués côté serveur avec des claims fiables, jamais depuis les métadonnées modifiables du profil utilisateur.

## Sécurité et limites d'analyse
L'analyse statique ne prouve ni l'existence ni l'absence d'une vulnérabilité. Aucun code distant n'est exécuté et aucun fichier n'est modifié. Les alertes sont des pistes à vérifier. Le mode ZIP traite les fichiers dans le navigateur, avec JSZip chargé depuis jsDelivr. L'URL d'un site audité est transmise à Google PageSpeed Insights.
