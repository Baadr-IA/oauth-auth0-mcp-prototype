# Standalone Auth0 + MCP prototype

This folder is isolated from the plugin workspace so the OAuth/Auth0 test can be run on its own.

## Pourquoi j’ai fait ce prototype

Le passage le plus important que je veux m’assurer qu’il fonctionne, c’est la chaîne d’identité de bout en bout :
Auth0 émet un access token valide, Alpic le transmet à mon serveur MCP, le backend valide le JWT,
et je peux mapper de façon fiable `org_id` vers `cabinet_id`.

Pour m’en assurer, je suis passé par un prototype minimal au lieu de brancher Turso tout de suite.
Ça m’a permis d’isoler la couche identité et transport du reste de l’application.

Pour tester ça, je n’ai exposé que la surface la plus simple utile :

- `GET /health` pour le contrôle public
- `GET /whoami` pour le contrôle HTTP protégé
- `POST /mcp` avec un seul outil `whoami()` pour le contrôle MCP protégé

Comme ça, je peux prouver que le chemin d’authentification fonctionne avant d’ajouter la persistance ou la logique métier.

## Endpoints

- `GET /health`
- `GET /whoami`
- `POST /mcp`

## Environment

Set these variables in Alpic:

- `AUTH0_DOMAIN=xxx.eu.auth0.com`
- `AUTH0_AUDIENCE=https://memoire-classification-api`
- `ENV=production`

Optional but useful:

- `AUTH0_ISSUER=https://xxx.eu.auth0.com/`
- `AUTH0_JWKS_URL=https://xxx.eu.auth0.com/.well-known/jwks.json`
- `CABINET_ID_BY_ORG_JSON={"org_123":"cabinet-a"}`
- `DEFAULT_CABINET_ID=cabinet-a`

For local tests, `AUTH0_JWKS_JSON` can hold a JWKS document directly.

## Run

```bash
python server.py --host 127.0.0.1 --port 8000
```

## Test

```bash
python -m unittest discover -s tests
```

## What this proves

- `/health` works without auth
- `/whoami` rejects missing tokens
- `/whoami` accepts a valid Auth0 RS256 access token
- `org_id` is extracted from the token
- `cabinet_id` is resolved from the organization metadata
- the MCP `whoami()` tool returns the same identity payload
