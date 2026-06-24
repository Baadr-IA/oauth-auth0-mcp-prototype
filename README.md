# Standalone Auth0 + MCP prototype

This folder is isolated from the plugin workspace so the OAuth/Auth0 test can be run on its own.

For the full narrative, mistakes, and final working flow, see [AUTH0_PROTOTYPE_RUNBOOK.md](AUTH0_PROTOTYPE_RUNBOOK.md).

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

## Erreurs de déploiement que j’ai faites

- J’ai d’abord pris le mauvais runtime pour le code existant avant de réaligner le prototype sur le runtime réellement attendu par Alpic.
- J’ai oublié `pyproject.toml`, ce qui a cassé le build Python avec `No pyproject.toml found`.
- J’ai oublié `uv.lock`, alors qu’Alpic lance le build Python en mode figé avec `UV_FROZEN=1`.
- J’ai oublié `main.py`, alors qu’Alpic essayait de démarrer le serveur avec ce point d’entrée.
- J’ai hardcodé le port `8000` au lieu de lire le port fourni par l’environnement Alpic, ce qui peut empêcher la connexion même si le déploiement est marqué comme réussi.

## Endpoints

- `GET /health`
- `GET /whoami`
- `POST /mcp`

## Environment

Set these variables in Alpic:

- `AUTH0_DOMAIN=dev-v4m6lbgizxmu1vhc.us.auth0.com`
- `AUTH0_AUDIENCE=<your Auth0 API identifier>`
- `ENV=production`

Optional but useful:

- `AUTH0_ISSUER=https://dev-v4m6lbgizxmu1vhc.us.auth0.com/`
- `AUTH0_JWKS_URL=https://dev-v4m6lbgizxmu1vhc.us.auth0.com/.well-known/jwks.json`
- `CABINET_ID_BY_ORG_JSON={"org_123":"cabinet-a"}`
- `DEFAULT_CABINET_ID=cabinet-a`
- `CORS_ALLOWED_ORIGINS=http://127.0.0.1:3000`
- `PUBLIC_BASE_URL=https://your-alpic-deployment-url`

For local tests, `AUTH0_JWKS_JSON` can hold a JWKS document directly.

The server now exposes OAuth discovery metadata at:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

## Run

Backend:

```bash
python server.py --host 127.0.0.1 --port 8000
```

Local Auth0 token helper:

```bash
python client_server.py --host 127.0.0.1 --port 3000
```

Then open `http://127.0.0.1:3000/`, sign in, and copy the access token.

If the project is installed as a package, the console script is:

```bash
oauth-auth0-mcp-prototype
```

Alpic can also start the repository entrypoint directly from `main.py`.

## Local Auth0 setup

In the Auth0 SPA application, set:

- Allowed Callback URLs: `http://127.0.0.1:3000/callback`
- Allowed Logout URLs: `http://127.0.0.1:3000/`
- Allowed Web Origins: `http://127.0.0.1:3000`
- Allowed Origins (CORS): `http://127.0.0.1:3000`

If you want the page button to call the backend directly, start the backend with:

```bash
$env:CORS_ALLOWED_ORIGINS="http://127.0.0.1:3000"
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
- the local client on port 3000 can complete Auth0 PKCE login and recover the access token
