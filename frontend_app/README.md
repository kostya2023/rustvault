# frontend_app

A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Learn Flutter](https://docs.flutter.dev/get-started/learn-flutter)
- [Write your first Flutter app](https://docs.flutter.dev/get-started/codelab)
- [Flutter learning resources](https://docs.flutter.dev/reference/learning-resources)

For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.

## Rust SDK end-to-end test

The `full_e2e_test` binary exercises the Rust SDK against a running RustVault
server, including account registration and deletion, TOTP and password flows,
vault encryption and storage, token rotation, security operations, and
passkeys via `webauthn-authenticator-rs`'s in-memory `SoftPasskey`.

Set `RUSTVAULT_E2E_PASSWORD` to a password for disposable test accounts. Set
`RUSTVAULT_API_URL` to the server URL if it is not `http://127.0.0.1:3000`,
and set `RUSTVAULT_E2E_WEBAUTHN_ORIGIN` to the exact WebAuthn RP origin
configured by the server. Both URLs must include an explicit port, including
the default ports (`:80` for HTTP or `:443` for HTTPS). Run from `frontend_app/rust`:

```powershell
$env:RUSTVAULT_E2E_PASSWORD = "use-a-disposable-test-password"
$env:RUSTVAULT_API_URL = "http://127.0.0.1:3000"
$env:RUSTVAULT_E2E_WEBAUTHN_ORIGIN = "http://localhost:3000"
cargo run --bin full_e2e_test
```

For the public HTTPS deployment, include `:443` explicitly, for example
`https://rustvault.ru:443` (and use that exact origin if it matches the
backend's WebAuthn RP origin). The binary prints the effective port for each
URL before making requests and exits before creating accounts if a port is
missing.

The binary prints per-step `[ RUN ]`, `[ PASS ]`, and `[ FAIL ]` lines. It
creates two uniquely named accounts and deletes them at the end of a successful
run. If a run fails before cleanup, the generated usernames are printed at
startup; clean up those disposable accounts manually before retrying.

## Custom HTTPS CA

Every network client can add an optional PEM-encoded CA certificate when it is
created. Existing `new()` and `with_base_url()` constructors continue to use
the default Reqwest trust configuration. For example:

```rust
let ssl_ca_pinned_cert = std::fs::read("certs/rustvault-ca.pem")?;
let client = AccountClient::with_base_url_and_root_of_trust(
    "https://api.example.test".to_owned(),
    Some(ssl_ca_pinned_cert),
)?;
```

Use `new_with_root_of_trust(Some(ssl_ca_pinned_cert))` to use the configured
`RUSTVAULT_API_URL`. Pass `None` to either constructor to keep the default
trust configuration. The PEM certificate is added as an extra trusted root;
it does not disable normal hostname or certificate-chain validation, and
system roots remain trusted.
