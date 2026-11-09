# RustVault

**Secure, self-hosted password vault built with Rust and Flutter.**

RustVault is a password management system designed with security, privacy, and performance in mind.

## Features

- **Password Authentication** — OPAQUE-based password authentication with TOTP.
- **Passkeys** — WebAuthn-based passwordless authentication.
- **End-to-End Encryption** — Client-side cryptographic operations.
- **Secure Vault Storage** — Encrypted vault data with integrity verification.
- **Session Management** — JWT access and refresh tokens with rotation and revocation.
- **Security Events** — Account activity and security change tracking.

## Tech Stack

| Component | Technologies |
|---|---|
| Backend | Rust, Axum, SQLx |
| Frontend | Flutter, Dart |
| SDK | Rust, Flutter Rust Bridge |
| Database | PostgreSQL |
| Cache | Redis |
| Object Storage | MinIO |
| Reverse Proxy | Nginx |

## Project Structure

```text
rustvault/
├── backend_app/    # Rust backend
├── frontend_app/   # Flutter application and Rust SDK
└── docs/           # API documentation
```

## Development

Backend infrastructure is managed using Docker Compose.

```bash
cd backend_app
docker compose up --build -d
```

See `backend_app/rustvault.env.example` for the environment configuration template.

## License

RustVault is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See [LICENSE](LICENSE) for licensing information.