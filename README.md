# Expense Tracker Authentication Service

Demo Spring Boot authentication and authorization service for the Expense Tracker demo application. It supports local signup with email verification, form login, OAuth2 social login, and Spring Authorization Server token issuance.

## Features

- Local user registration with email verification
- OAuth2 login with GitHub, Google, and Facebook
- Spring Authorization Server for OAuth2/OIDC clients
- Role-based access control for `USER` and `ADMIN`
- Redis-backed account lockout, rate limiting, and bearer-token revocation
- Verification-token expiration
- CORS startup validation with no wildcard origins
- Security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- Audit logging for authentication and admin events
- Request correlation with `X-Correlation-Id` for cross-service log lookup
- Flyway database migrations
- Actuator, Prometheus metrics, and OpenAPI documentation

## Tech Stack

- Java 17
- Spring Boot 3.3.0
- Spring Security 6
- Spring Authorization Server
- Spring Data JPA
- PostgreSQL for production
- H2 for development/tests
- Redis for temporary security state
- Flyway
- Maven
- Docker Compose

## Prerequisites

- Java 17+
- Docker and Docker Compose for production-like local runs
- Maven 3.8+ or the included Maven wrapper

## Profiles

| Setting | `dev` profile | `prod` profile |
|---------|---------------|----------------|
| Database | H2 in-memory | PostgreSQL |
| Flyway | Disabled | Enabled |
| H2 console | Enabled | Disabled |
| Account lockout | Disabled | Enabled |
| Rate limiting | Disabled | Enabled |
| Token blacklist | Disabled | Enabled |
| Verification token expiry | 720 hours | 24 hours |
| CORS origins | Localhost defaults | Explicit env var required |
| Logging | DEBUG | WARN root, INFO app |

No profile is active by default. Startup requires exactly one explicit profile: `dev` or `prod`.

## Local Manual Testing

Use `dev` for manual local testing. It avoids accidental lockouts and rate-limit noise while still exercising the signup, verification, login, and protected endpoint flows.

### 1. Start the App

```bash
./run-dev.sh
```

On Windows, use `run-dev.bat`.

The app starts at `http://localhost:9000`.

Useful URLs:
- Swagger UI: `http://localhost:9000/swagger-ui.html`
- Login page: `http://localhost:9000/login`
- Signup page: `http://localhost:9000/signup`
- H2 console: `http://localhost:9000/h2-console`

H2 console settings:
- JDBC URL: `jdbc:h2:mem:authdb`
- User: `sa`
- Password: `password`

To also create a local admin account at startup, run:

```bash
ADMIN_BOOTSTRAP_ENABLED=true \
ADMIN_BOOTSTRAP_EMAIL=admin@example.com \
ADMIN_BOOTSTRAP_PASSWORD=AdminPassword123! \
ADMIN_BOOTSTRAP_DISPLAY_NAME=Local Admin \
./run-dev.sh
```

The bootstrap is idempotent. If `admin@example.com` already exists, the app does not create another account. It promotes the existing account to `ADMIN` if needed and only resets the password when `ADMIN_BOOTSTRAP_RESET_PASSWORD=true`.

This application is designed for a single admin account. The admin API cannot assign the `ADMIN` role to other users.

### 2. Register a Local User

Use Swagger or curl:

```bash
curl -i -X POST http://localhost:9000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!","displayName":"Test User"}'
```

Expected result: `200 OK`.

### 3. Get the Verification Token in Dev

Verification tokens are no longer logged. For local dev, inspect H2 (see Useful URLs section above for H2 console link):

```sql
SELECT email, verification_token, verification_token_created_at, email_verified
FROM app_users
WHERE email = 'test@example.com';
```

Copy the `verification_token`.

### 4. Verify the Email

Use Swagger or curl:

```bash
curl -i "http://localhost:9000/api/auth/verify-email?token=<verification-token>"
```

Expected result: `200 OK`. The user becomes enabled and email-verified.

### 5. Login with the Browser Session

Open `http://localhost:9000/login` and log in with:

- Email: `test@example.com`
- Password: `SecurePass123!`

Then call the session-protected profile endpoint in the same browser:

```text
http://localhost:9000/api/auth/me
```

Expected result: a JSON profile for the logged-in user.

### 6. Test Resend Verification

Register another user, then call:

```bash
curl -i -X POST "http://localhost:9000/api/auth/resend-verification?email=another@example.com"
```

Check H2 again for the new token and timestamp.

### 7. Get an Access Token for `expense-tracker-api`

To get a bearer token for `expense-tracker-api`, use the authorization-code flow with PKCE.

Start auth in dev mode:

```bash
./run-dev.sh
```

The `dev` profile registers a public OAuth2 client for Postman and the local web app:

| Client setting | Dev value |
|----------------|-----------|
| Client ID | `expense-tracker-web` |
| Public client | `true` |
| Redirect URIs | `https://oauth.pstmn.io/v1/callback`, `https://oauth.pstmn.io/v1/browser-callback`, `http://localhost:5173/auth/callback` |
| Scopes | `openid profile` |

To override the default dev client, start auth with explicit variables:

```bash
AUTH_CLIENT_ENABLED=true \
AUTH_CLIENT_ID=expense-tracker-web \
AUTH_CLIENT_PUBLIC_CLIENT=true \
AUTH_CLIENT_REDIRECT_URIS=https://oauth.pstmn.io/v1/callback,https://oauth.pstmn.io/v1/browser-callback,http://localhost:5173/auth/callback \
./run-dev.sh
```

The OAuth client is required because `/oauth2/authorize` and `/oauth2/token` issue tokens only for registered clients. In dev mode, the client is stored in the in-memory H2 database at startup.

Sign up, verify the email, and log in at:

```text
http://localhost:9000/login
```

Then use Postman (Authorization tab):

| Field | Value |
|-------|-------|
| Authorization Type | `OAuth 2.0` |
| Grant Type | `Authorization Code with PKCE` |
| Auth URL | `http://localhost:9000/oauth2/authorize` |
| Access Token URL | `http://localhost:9000/oauth2/token` |
| Client ID | `expense-tracker-web` |
| Client Secret | Leave blank |
| Client Authentication | `Send client credentials in body` |
| Code Challenge Method | `SHA-256` |
| Redirect URI / Callback URL | Use the Postman-provided callback URL, usually `https://oauth.pstmn.io/v1/callback` or `https://oauth.pstmn.io/v1/browser-callback` |
| Scope | `openid profile` |

This dev client is a public PKCE client, so do not provide a client secret even though Postman asks how to send client credentials.
If Postman opens an external browser and the callback URL field is locked, it commonly uses `https://oauth.pstmn.io/v1/browser-callback`; keep that exact URL in `AUTH_CLIENT_REDIRECT_URIS`.

Click `Get New Access Token`. Postman opens the authorization flow, uses the active login session, and exchanges the authorization code with:

```text
POST http://localhost:9000/oauth2/token
```

Copy the returned `access_token` and call `expense-tracker-api` with it:

```bash
curl -i http://localhost:<expense-tracker-api-port>/<endpoint> \
  -H "Authorization: Bearer <access_token>"
```

If `expense-tracker-api` is running with its `prod` profile, make sure it trusts this auth service as the issuer, typically:

```bash
AUTH_ISSUER_URI=http://localhost:9000
```

### 8. Test Admin Access Locally

Start the app with the admin bootstrap variables above, then log in at:

```text
http://localhost:9000/login
```

Use:

- Email: `admin@example.com`
- Password: `AdminPassword123!`

In the same browser session, call:

```text
http://localhost:9000/api/admin/users
```

Expected result: `200 OK` with a user list. Password hashes are returned as `[PROTECTED]`.

You can also test with curl after logging in through a cookie-aware client, but the browser flow is simpler for manual local testing because the admin endpoints accept the normal Spring session.

## Production Profile Deployment

Production uses Docker Compose with PostgreSQL and Redis. The compose file runs the app with `SPRING_PROFILES_ACTIVE=prod`.

### 1. Create `.env`

Start from `.env.sample` and set production values:

```bash
cp .env.sample .env
```

Required production values:

```env
DB_NAME=expense_tracker_auth
DB_USERNAME=postgres
DB_PASSWORD=<strong-password>

ALLOWED_ORIGIN_PATTERNS=https://your-frontend.example.com
AUTH_ISSUER_URI=https://auth.example.com
VERIFICATION_BASE_URL=https://auth.example.com/verify-email
FRONTEND_BASE_URL=https://your-frontend.example.com

SMTP_HOST=<smtp-host>
SMTP_PORT=587
SMTP_USERNAME=<smtp-user>
SMTP_PASSWORD=<smtp-password>
SMTP_AUTH=true
SMTP_STARTTLS_ENABLE=true
MAIL_HEALTH_ENABLED=true

TRACING_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318/v1/traces

AUTH_CLIENT_ENABLED=true
AUTH_CLIENT_ID=expense-tracker-web
AUTH_CLIENT_PUBLIC_CLIENT=true
AUTH_CLIENT_REDIRECT_URIS=https://your-frontend.example.com/auth/callback
AUTH_CLIENT_POST_LOGOUT_REDIRECT_URIS=https://your-frontend.example.com/logout
AUTH_CLIENT_SCOPES=openid,profile

REDIS_HOST=redis
REDIS_PORT=6379

ADMIN_BOOTSTRAP_ENABLED=true
ADMIN_BOOTSTRAP_EMAIL=admin@your-domain.example
ADMIN_BOOTSTRAP_PASSWORD=<strong-admin-password-at-least-12-chars>
ADMIN_BOOTSTRAP_DISPLAY_NAME=Administrator
ADMIN_BOOTSTRAP_RESET_PASSWORD=false
```

`ALLOWED_ORIGIN_PATTERNS` is required in production. Wildcards such as `*` are rejected at startup.

`FRONTEND_BASE_URL` is used as the fallback destination after a direct auth login or successful email verification. The normal OIDC flow still redirects to the saved `/auth/callback` request when login starts from the frontend.

`AUTH_CLIENT_POST_LOGOUT_REDIRECT_URIS` must include the frontend logout page. For the local Vue frontend, use `http://localhost:5173/logout`.

Admin bootstrap notes:
- Leave `ADMIN_BOOTSTRAP_ENABLED=false` after the first successful deployment if you do not want startup to keep checking/promoting the account.
- If the configured email already exists, no duplicate account is created.
- If the existing account lacks `ADMIN`, it is promoted.
- The password is not reset on later startups unless `ADMIN_BOOTSTRAP_RESET_PASSWORD=true`.
- The configured bootstrap admin is the only supported admin account. `PUT /api/admin/users/{id}/roles` rejects `roleName=ADMIN`.

### 2. Start Production Profile

```bash
docker compose --env-file .env up --build
```

The compose stack starts:
- `db`: PostgreSQL 15
- `redis`: Redis 7
- `auth`: the Spring Boot auth service

Check health:

```bash
docker compose ps
docker compose logs auth
```

### 3. Verify Production Startup

Expected startup behavior:
- Flyway applies migrations, including `V2__add_security_mitigations.sql`
- H2 console is disabled
- Redis-backed account lockout is enabled
- Redis-backed rate limiting is enabled
- Token blacklist is enabled
- CORS validation rejects blank or wildcard origins

Health endpoint:

```bash
curl -i http://localhost:9000/actuator/health
```

### Refresh Local Prod Database

This deletes the local auth PostgreSQL volume. Use only when you intentionally want to remove all local prod auth users, clients, authorization records, and audit data.

Check the volume name first:

```bash
docker volume ls | grep expense-tracker-auth
```

Then refresh from the `expense-tracker-auth` directory:

```bash
docker compose --env-file .env down
docker volume rm expense-tracker-auth_auth-pgdata
docker compose --env-file .env up --build -d
```

### 4. Production Manual Smoke Test

Signup:

```bash
curl -i -X POST http://localhost:9000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"prod-smoke@example.com","password":"SecurePass123!","displayName":"Prod Smoke"}'
```

Confirm that a real verification email is delivered through SMTP. In production, verification tokens are not logged.

Verify using the email link, then log in through:

```text
http://localhost:9000/login
```

Admin smoke test:

1. Log in as the configured `ADMIN_BOOTSTRAP_EMAIL`.
2. Open `http://localhost:9000/api/admin/users` in the same browser session.
3. Confirm the response is `200 OK`.
4. Confirm another user cannot be promoted to admin through the API:

```bash
curl -i -X PUT "http://localhost:9000/api/admin/users/<user-id>/roles?roleName=ADMIN"
```

Expected result: `400 Bad Request`.

5. Optionally disable bootstrap after confirming admin access:

```env
ADMIN_BOOTSTRAP_ENABLED=false
```

Then redeploy. The already-created admin account remains in the database.

### 5. Production Security Checks

Account lockout:

```bash
for i in {1..5}; do
  curl -i -X POST http://localhost:9000/login \
    -d "email=prod-smoke@example.com&password=wrongpass"
done
```

The account is locked temporarily after the configured threshold.

Rate limiting:

```bash
for i in {1..105}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:9000/api/auth/me
done
```

Requests above the configured limit return `429`.

Token revocation:
- Call `POST /api/auth/logout` with the bearer token.
- Subsequent requests to this auth service with the same token return `401`.
- Downstream services must also consult the same blacklist or use token introspection if they need immediate revocation.

## Observability

The auth service supports simple HTTP request correlation with `X-Correlation-Id`.

- If the caller sends `X-Correlation-Id`, the service reuses it.
- If the caller omits it, the service generates a UUID.
- The same value is returned in the response header.
- Logs include `correlationId=...` together with existing `traceId` and `spanId` fields.
- The header is allowed and exposed by CORS for browser clients.

Example:

```bash
curl -i http://localhost:9000/api/auth/verify-email?token=missing \
  -H "X-Correlation-Id: manual-auth-test-123"
```

Search auth logs for:

```text
correlationId=manual-auth-test-123
```

`X-Correlation-Id` is operational metadata only. It is not a JWT claim and is not persisted.

## Configuration Properties

| Property | Purpose |
|----------|---------|
| `app.cors.allowed-origin-patterns` | Comma-separated allowed origins |
| `app.security.verification-token-expiration-hours` | Verification token lifetime |
| `app.security.account-lockout.enabled` | Enable account lockout |
| `app.security.account-lockout.max-attempts` | Failed login threshold |
| `app.security.account-lockout.duration-minutes` | Lockout TTL |
| `app.security.rate-limiting.enabled` | Enable auth endpoint rate limiting |
| `app.security.rate-limiting.requests-per-minute` | Per-IP limit |
| `app.security.token-blacklist.enabled` | Enable bearer-token blacklist checks |
| `spring.data.redis.host` | Redis host |
| `spring.data.redis.port` | Redis port |
| `app.auth.issuer-uri` | Authorization server issuer |
| `app.auth.verification-base-url` | Email verification link base URL |
| `app.auth.client.*` | Default registered OAuth2 client settings |
| `app.admin.bootstrap.enabled` | Enable one-time admin bootstrap |
| `app.admin.bootstrap.email` | Bootstrap admin email |
| `app.admin.bootstrap.password` | Bootstrap admin password |
| `app.admin.bootstrap.display-name` | Bootstrap admin display name |
| `app.admin.bootstrap.reset-password` | Reset existing bootstrap admin password on startup |

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/signup` | Register local user | No |
| `GET` | `/api/auth/verify-email` | Verify email token | No |
| `POST` | `/api/auth/resend-verification` | Generate a new verification token | No |
| `POST` | `/api/auth/logout` | Revoke presented bearer token and invalidate session | No |
| `GET` | `/api/auth/me` | Current user profile | Yes |

### Form and OAuth2

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/login` | Login page |
| `POST` | `/login` | Form login |
| `GET` | `/oauth2/authorization/{provider}` | Social login start |
| `GET` | `/oauth2/authorize` | Authorization endpoint |
| `POST` | `/oauth2/token` | Token endpoint |
| `GET` | `/oauth2/jwks` | JWK set |

### Admin

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/admin/users` | List users | `ADMIN` |
| `PUT` | `/api/admin/users/{id}/status` | Enable/disable user | `ADMIN` |
| `PUT` | `/api/admin/users/{id}/roles` | Assign non-admin role; `ADMIN` is rejected | `ADMIN` |

## Database Schema

Migrations live in `src/main/resources/db/migration/`.

Key tables:
- `app_users`
- `roles`
- `user_roles`
- `audit_logs`
- Spring Authorization Server tables prefixed with `oauth2_`

## Testing

Run all tests:

```bash
./mvnw test
```

Current test coverage includes:
- Auth service unit tests
- Signup integration tests
- Expired verification token integration test

## Troubleshooting

### Production Fails on CORS Configuration

Set `ALLOWED_ORIGIN_PATTERNS` to explicit origins:

```env
ALLOWED_ORIGIN_PATTERNS=https://your-frontend.example.com
```

Do not use `*`.

### Verification Email Not Received

- Check `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, and `SMTP_PASSWORD`.
- For Gmail, use an app password and set `SMTP_AUTH=true`, `SMTP_STARTTLS_ENABLE=true`, and `MAIL_HEALTH_ENABLED=true`.
- For local prod integration without real email, use `SMTP_HOST=localhost`, `SMTP_PORT=1025`, blank SMTP credentials, `SMTP_AUTH=false`, `SMTP_STARTTLS_ENABLE=false`, and `MAIL_HEALTH_ENABLED=false`.
- Check `VERIFICATION_BASE_URL`.
- Inspect `docker compose logs auth`.
- In dev only, inspect H2 for `verification_token`.

For local `prod` integration with dummy SMTP, activate a test account by reading the verification token from PostgreSQL and calling the normal verify endpoint:

```bash
docker compose --env-file .env exec db psql \
  -U postgres \
  -d expense_tracker_auth \
  -c "SELECT email, verification_token, verification_token_created_at, email_verified FROM app_users WHERE email = 'your-email@example.com';"
```

Open the web verification page:

```text
http://localhost:9000/verify-email?token=<verification-token>
```

Or call the REST endpoint:

```bash
curl -i "http://localhost:9000/api/auth/verify-email?token=<verification-token>"
```

If the token expired, generate a new one and query the database again:

```bash
curl -i -X POST "http://localhost:9000/api/auth/resend-verification?email=your-email@example.com"
```

After verification, open the frontend and click **Continue with SSO**. A direct login on the auth service creates an auth-server session, but the frontend still needs to start the OIDC flow to receive its access token.

### OTLP Export Fails on `localhost:4318`

Set `TRACING_ENABLED=false` for local prod integration without an OpenTelemetry Collector. If you run a collector, set `TRACING_ENABLED=true` and point `OTEL_EXPORTER_OTLP_ENDPOINT` to a container-reachable collector URL.

### Account Locked

Production lockout keys use the Redis prefix:

```text
auth:account_locked:<email>
auth:failed_attempts:<email>
```

To inspect:

```bash
docker compose exec redis redis-cli KEYS 'auth:*'
```

### Rate Limited

Rate limit keys use:

```text
auth:rate_limit:<ip>
```

Wait one minute or adjust `RATE_LIMIT_REQUESTS_PER_MINUTE`.

### Redis Connection Issues

```bash
docker compose ps redis
docker compose exec redis redis-cli ping
```

Expected response: `PONG`.

### Database Connection Issues

```bash
docker compose ps db
docker compose logs db
```

Confirm `.env` database values match the PostgreSQL container environment.

## Development Notes

To add a Flyway migration, create a file like:

```text
src/main/resources/db/migration/V3__description.sql
```

Then run the app with the `prod` profile or run the relevant Flyway/Maven task against a configured database.
