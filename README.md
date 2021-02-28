# Goberge

Goberge est une librairie générique qui permet d'implémenter la gestion de JSON web tokens dans une API utilisant gin-gonic.

## Pré-requis

Pour utiliser la lib, il est nécessaire de définir la variable d'environnement "SECRET_KEY", qui sera utilisée pour chiffrer les signatures des tokens.

Exemple:
`SECRECT_KEY=qwerty12345`

Il est également possible, mais facultatif, de définir les variables "TOKEN_LIMIT_HOURS" et "TOKEN_VALIDITY_MINUTES", qui ont pour valeur par défaut "24" et "15".

Exemple:
`TOKEN_LIMIT_HOURS=48`
`TOKEN_VALIDITY_MINUTES=30`

## Fonctionnement

La lib contient trois fonctions principales:

`RefreshToken` qui peut etre appellée directement par une route, elle lit le token du contexte gin passé en paramètre, et en renvoie un nouveau si la date limite de rafrachissement du token passé en paramètre n'est pas dépassée.

`GenerateToken` génère et renvoie un token sous forme d'une chaine de caractère.

`VerifyToken` prend en paramètre un token sous forme d'une string, et vérifie s'il est valide et n'a pas été modifié. Cette fonction est sensée être appelée dans les middleware.

TOKEN_LIMIT_HOURS représente en heures, la limite de rafraichissement d'un token. Quand cette durée est dépassée, le token ne peut plus être rafraichit, l'utilisateur doit donc se reconnecter.

TOKEN_VALIDITY_MINUTES représente en minutes, la durée de validité d'un token. Quand cette durée est dépassée, le doit être rafraichit.

## Conseils d'utilisation

Cette lib sera parfaite pour fonctionner avec un front-end qui rafraichit ses tokens dans un intercepteur.
