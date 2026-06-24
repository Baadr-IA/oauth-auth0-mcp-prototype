# Auth0 / MCP prototype runbook

I built this prototype to verify one thing end to end:

Auth0 login -> Alpic transport -> backend JWT validation -> `org_id` extraction -> `cabinet_id` mapping.

I did not want to connect Turso too early, because the real risk was identity and tenant routing, not persistence.

## What I built

- A minimal Python backend
- `GET /health` for a public check
- `GET /whoami` for a protected HTTP check
- `POST /mcp` with one tool: `whoami()`
- A small local client on port `3000` that performs Auth0 PKCE login and recovers the access token
- OAuth discovery metadata so Alpic can recognize the server as OAuth-protected

## What I configured in Auth0

### Auth0 tenant

- Domain: `dev-v4m6lbgizxmu1vhc.us.auth0.com`

### Custom API

- Name: `memoire-classification-api`
- Identifier / audience: the Auth0 API identifier I actually used for the token flow

### SPA application

- Application: `memoire-classification-api2`
- Redirect URI: `http://127.0.0.1:3000/callback`
- Logout URI: `http://127.0.0.1:3000/`
- Web origin: `http://127.0.0.1:3000`

### Organization

- Organization name: `cabinet-a`
- Organization ID: `org_SnJuASS3AvpItj4X`

The important part is that the login request uses the Organization ID, not the display name.

## The mistakes I made

- I started with the wrong runtime assumption for deployment.
- I forgot `pyproject.toml`, which broke the Python build.
- I forgot `uv.lock`, which broke the frozen build mode.
- I forgot `main.py`, so the deployment had no entrypoint.
- I hardcoded port `8000` instead of respecting the runtime environment.
- I initially used a machine-to-machine mental model for a user login flow.
- I tried `cabinet-a` as the `organization` request parameter, but Auth0 expects the Organization ID.
- I hit `invalid_request: parameter organization is not allowed for this client` until the app was configured to support Organizations.
- I had to stop persisting `organization` locally, otherwise an old value kept coming back during tests.

## Backend behavior

The backend now validates:

- JWT signature
- issuer
- audience
- expiration
- `org_id`

It resolves:

- `org_id` -> `cabinet_id`

If the token is valid but has no `org_id`, `/whoami` returns `missing org_id`.

It also exposes discovery documents for Alpic:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

For deployment, I set `PUBLIC_BASE_URL` to the public Alpic URL so the metadata points to the right origin.

## Local test flow

### 1. Start the backend

```bash
python server.py --host 127.0.0.1 --port 8000
```

### 2. Start the local Auth0 helper

```bash
python client_server.py --host 127.0.0.1 --port 3000
```

### 3. Open the client

Go to:

```text
http://127.0.0.1:3000/
```

### 4. Log in

I first make sure the login flow works, then I send the organization only when Auth0 allows it and the org is properly configured.

### 5. Test `/whoami`

```powershell
$token = "<paste the access token>"
Invoke-RestMethod http://127.0.0.1:8000/whoami -Headers @{ Authorization = "Bearer $token" }
```

Expected result:

```json
{
  "sub": "google-oauth2|...",
  "org_id": "org_SnJuASS3AvpItj4X",
  "cabinet_id": "cabinet-a"
}
```

## What finally worked

The successful check returned:

- `sub = google-oauth2|106171528598363769198`
- `org_id = org_SnJuASS3AvpItj4X`
- `cabinet_id = cabinet-a`

That confirmed the full chain:

- Auth0 issued a user token
- the backend accepted it
- the organization claim was present
- the organization mapped to the cabinet

## What I learned

- `cabinet-a` is the human name, not the Auth0 request value.
- The request must use the Organization ID.
- A token without `org_id` is not enough for this prototype.
- The prototype is useful only if identity and tenant routing work before persistence.
