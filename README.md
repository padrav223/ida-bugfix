# IDA BugFix

Prototype indépendant d'un assistant de diagnostic et de correction de bugs, en français et adapté au mobile.

## État actuel

La première version est une maquette d'interface avec diagnostics fictifs. Elle ne télécharge pas encore de dépôt, n'exécute pas de code distant, n'appelle pas de modèle IA et ne modifie aucun projet.

## Feuille de route

1. Récupération contrôlée des fichiers d'un dépôt GitHub.
2. Analyse statique : secrets exposés, configuration, lint et types.
3. Exécution des tests dans un environnement isolé, sans accès réseau et avec limites de ressources.
4. Aide IA côté serveur, sans exposer les clés dans le navigateur.
5. Correctifs proposés en diff sur une branche dédiée.
6. Validation humaine obligatoire avant toute application.

## Sécurité

Tout dépôt analysé est non fiable. Aucun code utilisateur ne doit être exécuté sur le serveur principal. Ne jamais demander de mot de passe ou de token dans l'interface. Ne jamais modifier automatiquement la branche principale.

## Lancement

Ouvrir `index.html` dans un navigateur. Aucun outil ou téléchargement n'est nécessaire pour cette maquette.
