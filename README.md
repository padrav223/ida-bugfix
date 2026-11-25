# IDA BugFix 2.2.0 — plateforme de diagnostic et fondations SaaS

IDA BugFix propose trois entrées de diagnostic : dépôts GitHub publics, archives ZIP locales et audits de sites via Google PageSpeed Insights / Lighthouse.

## Fonctions disponibles dans l'application
- Analyse statique heuristique GitHub (jusqu'à 60 fichiers texte).
- Analyse ZIP locale dans le navigateur (limites indiquées dans l'interface).
- Audit web Lighthouse via PageSpeed Insights.
- Historique local des 20 derniers rapports, filtres, export JSON et impression PDF.
- Plan de correction priorisé à partir des alertes : recommandations et étapes de vérification, sans modification automatique du code.

## Fondations SaaS ajoutées en 2.2.0
- Interface de création de compte et de connexion par e-mail avec Supabase Auth.
- Synchronisation des rapports vers une base Supabase après configuration et authentification.
- Tableau de bord client avec identité, formule et nombre de rapports synchronisés.
- Schéma SQL pour profils, rapports et licences, avec Row Level Security et politiques d'accès par propriétaire.
- Structure d'offres Free, Pro et Team et statut de licence administrable côté serveur.
- Zone explicative réservée à l'exécution isolée des tests.

## Activation cloud
1. Créer un projet Supabase dédié à IDA BugFix (ne pas réutiliser les identifiants d'un autre projet).
2. Exécuter `supabase/schema.sql` dans l'éditeur SQL du nouveau projet.
3. Dans IDA BugFix, renseigner l'URL du projet et sa clé publique (publishable ou anon).
4. Créer un compte puis se connecter. Les nouveaux rapports seront synchronisés après connexion.
5. Pour attribuer une formule Pro/Team, l'administrateur doit mettre à jour la licence depuis un environnement serveur protégé.

La configuration Supabase saisie dans le navigateur est conservée localement. Ne jamais utiliser une clé `service_role` ou une clé secrète dans le navigateur.

## Ce qui n'est pas encore activé
- Aucun projet Supabase n'est préconfiguré et aucun compte cloud n'est créé automatiquement.
- Aucun prestataire de paiement (Stripe, PayDunya, etc.) ni webhook de paiement n'est raccordé : les offres affichées ne déclenchent aucun prélèvement.
- Aucun moteur n'exécute le code client. L'exécution de code non fiable exige un service sandbox isolé, avec quotas, réseau restreint, limites de ressources et suppression des environnements.
- Les corrections sont des recommandations, pas des patchs automatiques ni des garanties de résolution.
- Les rôles d'administration et l'attribution des licences doivent être effectués côté serveur avec des claims fiables, jamais depuis les métadonnées modifiables du profil utilisateur.

## Sécurité et limites d'analyse
L'analyse statique ne prouve ni l'existence ni l'absence d'une vulnérabilité. Aucun code distant n'est exécuté et aucun fichier n'est modifié. Les alertes sont des pistes à vérifier. Le mode ZIP traite les fichiers dans le navigateur, avec JSZip chargé depuis jsDelivr. L'URL d'un site audité est transmise à Google PageSpeed Insights.
