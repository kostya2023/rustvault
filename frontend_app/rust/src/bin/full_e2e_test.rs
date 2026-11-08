use std::{
    error::Error,
    io,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use rust_lib_frontend_app::api::{
    clients::{
        account_client::AccountClient,
        auth_client::{
            LoginWithPasskeyClient, LoginWithPasstotpClient, RegistrationWithPasstotpClient,
            TokenClient,
        },
        crypto_client::CryptoClient,
        health_client::HealthClient,
        security_client::SecurityClient,
        vault_client::VaultClient,
    },
    types::{
        blob::Blob,
        crypto::{BlobHandler, Key, Keys, TbsBlob},
        master_key::MasterKey,
    },
};
use totp_rs::Totp;
use webauthn_authenticator_rs::{
    AuthenticatorBackend,
    prelude::{CreationChallengeResponse, RequestChallengeResponse, Url},
    softpasskey::SoftPasskey,
};

type E2eResult<T> = Result<T, Box<dyn Error>>;

static PASSED: AtomicUsize = AtomicUsize::new(0);

fn require_explicit_port(label: &str, value: &str) -> E2eResult<()> {
    let parsed = reqwest::Url::parse(value)?;
    let authority = value
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .ok_or_else(|| io::Error::other(format!("{label} must include a scheme and host")))?;
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let explicit_port = if host_port.starts_with('[') {
        host_port
            .find(']')
            .and_then(|close| host_port.get(close + 1..))
            .and_then(|suffix| suffix.strip_prefix(':'))
            .map(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
            .unwrap_or(false)
    } else {
        host_port
            .rsplit_once(':')
            .map(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
            .unwrap_or(false)
    };

    if !explicit_port {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must specify an explicit port, for example https://example.test:443"),
        )));
    }

    let port = parsed.port_or_known_default().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must use a URL scheme with a known port"),
        )
    })?;
    println!("[ INFO ] {label} uses port {port}");
    Ok(())
}

fn checked<T, E: std::fmt::Display>(label: &str, result: Result<T, E>) -> E2eResult<T> {
    println!("[ RUN  ] {label}");
    match result {
        Ok(value) => {
            println!("[ PASS ] {label}");
            PASSED.fetch_add(1, Ordering::Relaxed);
            Ok(value)
        }
        Err(error) => {
            println!("[ FAIL ] {label}: {error}");
            Err(Box::new(io::Error::other(format!("{label}: {error}"))))
        }
    }
}

fn require(label: &str, condition: bool) -> E2eResult<()> {
    if condition {
        println!("[ PASS ] {label}");
        PASSED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        println!("[ FAIL ] {label}");
        Err(Box::new(io::Error::other(label.to_owned())))
    }
}

fn expect_error<T, E: std::fmt::Display>(label: &str, result: Result<T, E>) -> E2eResult<()> {
    match result {
        Ok(_) => {
            println!("[ FAIL ] {label}: expected the server to reject this request");
            Err(Box::new(io::Error::other(format!(
                "{label}: expected rejection"
            ))))
        }
        Err(error) => {
            println!("[ PASS ] {label}: rejected as expected ({error})");
            PASSED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
}

fn new_master_key(password: &str, username: &str) -> E2eResult<MasterKey> {
    Ok(MasterKey::new(password.as_bytes(), username.as_bytes())?)
}

fn totp_from_url(totp_url: String) -> E2eResult<Totp> {
    Ok(Totp::from_url(totp_url)?)
}

fn make_registration_credential(
    authenticator: &mut SoftPasskey,
    challenge_json: &str,
    origin: &str,
) -> E2eResult<String> {
    let challenge: CreationChallengeResponse = serde_json::from_str(challenge_json)?;
    let origin: Url = origin.parse()?;
    let credential = authenticator.perform_register(origin, challenge.public_key, 30_000)?;
    Ok(serde_json::to_string(&credential)?)
}

fn make_assertion_credential(
    authenticator: &mut SoftPasskey,
    challenge_json: &str,
    origin: &str,
) -> E2eResult<String> {
    let challenge: RequestChallengeResponse = serde_json::from_str(challenge_json)?;
    let origin: Url = origin.parse()?;
    let credential = authenticator.perform_auth(origin, challenge.public_key, 30_000)?;
    Ok(serde_json::to_string(&credential)?)
}

async fn run() -> E2eResult<()> {
    let base_url = std::env::var("RUSTVAULT_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned());
    let origin = std::env::var("RUSTVAULT_E2E_WEBAUTHN_ORIGIN")
        .unwrap_or_else(|_| base_url.clone());
    require_explicit_port("RUSTVAULT_API_URL", &base_url)?;
    require_explicit_port("RUSTVAULT_E2E_WEBAUTHN_ORIGIN", &origin)?;
    let password = std::env::var("RUSTVAULT_E2E_PASSWORD").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Set RUSTVAULT_E2E_PASSWORD to a disposable test-account password",
        )
    })?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let username = format!("e2e{timestamp:x}{:x}", std::process::id());
    let totp_username = format!("{username}t");

    println!("RustVault SDK full end-to-end test");
    println!("API: {base_url}");
    println!("WebAuthn origin: {origin}");
    println!("Disposable accounts: {username}, {totp_username}");
    println!("No passwords, TOTP values, or bearer tokens are printed.");

    let health = checked(
        "Construct HealthClient",
        HealthClient::with_base_url(base_url.clone()),
    )?;
    let _health_default = checked("Construct HealthClient::new", HealthClient::new())?;
    let status = checked("GET /v1/healthz", health.check().await)?;
    require("Health response is non-empty", !status.status.is_empty())?;

    let registration = checked(
        "Construct RegistrationWithPasstotpClient",
        RegistrationWithPasstotpClient::with_base_url(base_url.clone()),
    )?;
    let _registration_default = checked(
        "Construct RegistrationWithPasstotpClient::new",
        RegistrationWithPasstotpClient::new(),
    )?;
    let login = checked(
        "Construct LoginWithPasstotpClient",
        LoginWithPasstotpClient::with_base_url(base_url.clone()),
    )?;
    let _login_default = checked(
        "Construct LoginWithPasstotpClient::new",
        LoginWithPasstotpClient::new(),
    )?;
    let passkey_login = checked(
        "Construct LoginWithPasskeyClient",
        LoginWithPasskeyClient::with_base_url(base_url.clone()),
    )?;
    let _passkey_login_default = checked(
        "Construct LoginWithPasskeyClient::new",
        LoginWithPasskeyClient::new(),
    )?;
    let tokens = checked(
        "Construct TokenClient",
        TokenClient::with_base_url(base_url.clone()),
    )?;
    let _tokens_default = checked("Construct TokenClient::new", TokenClient::new())?;
    let account = checked(
        "Construct AccountClient",
        AccountClient::with_base_url(base_url.clone()),
    )?;
    let _account_default = checked("Construct AccountClient::new", AccountClient::new())?;
    let security = checked(
        "Construct SecurityClient",
        SecurityClient::with_base_url(base_url.clone()),
    )?;
    let _security_default = checked("Construct SecurityClient::new", SecurityClient::new())?;
    let vault = checked(
        "Construct VaultClient",
        VaultClient::with_base_url(base_url.clone()),
    )?;
    let _vault_default = checked("Construct VaultClient::new", VaultClient::new())?;
    let crypto = checked("Construct CryptoClient", Ok::<_, io::Error>(CryptoClient::new()))?;
    // The server requires user verification; SoftPasskey simulates it in this test mode.
    let mut authenticator = SoftPasskey::new(true);

    let mut master_key = new_master_key(&password, &username)?;
    let fingerprint = checked(
        "MasterKey fingerprint",
        Ok::<_, io::Error>(master_key.fingerprint()),
    )?;
    require("MasterKey fingerprint format", fingerprint.len() == 32)?;
    let mut disposable_key = new_master_key("e2e-zeroize-check", &username)?;
    checked(
        "MasterKey zeroize",
        Ok::<_, io::Error>(disposable_key.zeroize()),
    )?;

    let registration_flow = checked(
        "RegistrationWithPasstotpClient::step1",
        registration.step1(username.clone(), &master_key).await,
    )?;
    require(
        "Registration flow exposes its operation ID",
        !registration_flow.operation_id().is_empty(),
    )?;
    let mut totp = checked(
        "Parse TOTP provisioning URI",
        totp_from_url(registration_flow.totp_url()),
    )?;
    let (access_token, refresh_token) = checked(
        "RegistrationWithPasstotpClient::step2",
        registration
            .step2(registration_flow, totp.generate_current().to_string())
            .await,
    )?;
    expect_error(
        "Client constructor rejects malformed base URLs",
        AccountClient::with_base_url("not-a-url".to_owned()),
    )?;

    let account_info = checked(
        "GET /v1/account",
        account.get_info(access_token.clone()).await,
    )?;
    require(
        "Account response matches the newly registered user",
        account_info.username == username,
    )?;
    let initial_events = checked(
        "GET /v1/security/events",
        security.get_events(access_token.clone(), 50, 0).await,
    )?;
    require(
        "Security events response is readable",
        !initial_events.is_empty(),
    )?;
    let initial_passkeys = checked(
        "GET /v1/security/passkeys (empty account)",
        security.get_passkeys(access_token.clone()).await,
    )?;
    require("New account initially has no passkeys", initial_passkeys.is_empty())?;

    let keys = Keys {
        keys: vec![Key {
            service_name: "e2e-service".to_owned(),
            password: "e2e-secret".to_owned(),
            username: "e2e-user".to_owned(),
            user_comment: "SDK end-to-end fixture".to_owned(),
        }],
    };
    let encoded_keys = checked("CBOR serialize Keys", crypto.serialize_keys(keys))?;
    let parsed_keys = checked("CBOR parse Keys", crypto.parse_keys(encoded_keys))?;
    require(
        "Keys CBOR preserves entry data",
        parsed_keys.keys.len() == 1
            && parsed_keys.keys[0].service_name == "e2e-service"
            && parsed_keys.keys[0].password == "e2e-secret",
    )?;

    let tbs_blob = TbsBlob {
        handler: BlobHandler {
            salt_verify: Vec::new(),
        },
        keys: parsed_keys,
    };
    let encoded_tbs = checked("CBOR serialize TbsBlob", crypto.serialize_tbs_blob(tbs_blob))?;
    let parsed_tbs = checked("CBOR parse TbsBlob", crypto.parse_tbs_blob(encoded_tbs))?;
    let encrypted_blob = checked("Encrypt + sign blob", crypto.encrypt(&master_key, parsed_tbs))?;
    let envelope_bytes = checked(
        "Serialize Blob CBOR envelope",
        encrypted_blob.serialize_cbor(),
    )?;
    let encrypted_copy = checked(
        "Parse Blob CBOR envelope",
        Blob::deserialize_cbor(envelope_bytes.clone()),
    )?;
    let encrypted_bytes = checked(
        "Read encrypted blob bytes",
        Ok::<_, io::Error>(encrypted_copy.encrypted_bytes()),
    )?;
    let signature = checked(
        "Read blob signature",
        Ok::<_, io::Error>(encrypted_copy.signature()),
    )?;
    require(
        "Blob contains ciphertext and Ed25519 signature",
        !encrypted_bytes.is_empty() && signature.len() == 64,
    )?;
    let blob_size = checked(
        "Read Blob size",
        Ok::<_, io::Error>(encrypted_copy.size()),
    )?;
    require("Blob size is non-zero", blob_size > 0)?;
    let rebuilt_blob = checked(
        "Construct Blob from encrypted bytes and signature",
        Ok::<_, io::Error>(Blob::new(encrypted_bytes.clone(), signature.clone())),
    )?;
    let rebuilt_envelope = checked("Serialize constructed Blob", rebuilt_blob.serialize_cbor())?;
    require("Blob constructor preserves the envelope", rebuilt_envelope == envelope_bytes)?;
    let mut tampered_bytes = encrypted_bytes.clone();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 1;
    expect_error(
        "Tampered ciphertext fails authenticated decryption",
        crypto.decrypt(&master_key, Blob::new(tampered_bytes, signature.clone())),
    )?;
    checked(
        "PUT /v1/blob (version 1)",
        vault.upload(access_token.clone(), encrypted_copy, 1).await,
    )?;
    let metadata_v1 = checked(
        "GET /v1/blob/meta",
        vault.get_metadata(access_token.clone()).await,
    )?;
    require("Blob metadata reports version 1", metadata_v1.version == 1)?;
    let downloaded_v1 = checked("GET /v1/blob", vault.download(access_token.clone()).await)?;
    let downloaded_v1_cbor = checked(
        "Serialize downloaded Blob",
        downloaded_v1.serialize_cbor(),
    )?;
    require(
        "Downloaded blob matches uploaded envelope",
        downloaded_v1_cbor == envelope_bytes,
    )?;
    let decrypted_v1 = checked(
        "Decrypt + verify downloaded blob",
        crypto.decrypt(&master_key, downloaded_v1),
    )?;
    require(
        "Decrypted blob has the expected entry",
        decrypted_v1.keys.keys.len() == 1
            && decrypted_v1.keys.keys[0].username == "e2e-user",
    )?;
    let bad_signature_blob = Blob::new(
        encrypted_bytes.clone(),
        vec![0; signature.len()],
    );
    expect_error(
        "Invalid Ed25519 signature is rejected",
        crypto.decrypt(&master_key, bad_signature_blob),
    )?;
    let duplicate_v1 = checked(
        "Rebuild Blob for stale-version test",
        Blob::deserialize_cbor(envelope_bytes.clone()),
    )?;
    expect_error(
        "PUT /v1/blob rejects a non-increasing version",
        vault.upload(access_token.clone(), duplicate_v1, 1).await,
    )?;

    let replacement = TbsBlob {
        handler: BlobHandler {
            salt_verify: Vec::new(),
        },
        keys: Keys {
            keys: vec![Key {
                service_name: "e2e-replacement".to_owned(),
                password: "second-secret".to_owned(),
                username: "second-user".to_owned(),
                user_comment: "version 2".to_owned(),
            }],
        },
    };
    let replacement = checked(
        "Encrypt replacement blob",
        crypto.encrypt(&master_key, replacement),
    )?;
    checked(
        "PUT /v1/blob (version 2 replacement)",
        vault.upload(access_token.clone(), replacement, 2).await,
    )?;
    let metadata_v2 = checked(
        "GET /v1/blob/meta after replacement",
        vault.get_metadata(access_token.clone()).await,
    )?;
    require("Blob metadata reports version 2", metadata_v2.version == 2)?;
    let downloaded_v2 = checked(
        "GET /v1/blob after replacement",
        vault.download(access_token.clone()).await,
    )?;
    let decrypted_v2 = checked(
        "Decrypt + verify replacement blob",
        crypto.decrypt(&master_key, downloaded_v2),
    )?;
    require(
        "Replacement payload was stored",
        decrypted_v2.keys.keys[0].service_name == "e2e-replacement",
    )?;

    let (_refreshed_access, refreshed_refresh) = checked(
        "POST /v1/auth/refresh",
        tokens.refresh(refresh_token.clone()).await,
    )?;
    expect_error(
        "Refresh token rotation rejects the previous refresh token",
        tokens.refresh(refresh_token).await,
    )?;
    let (rotated_access, _rotated_refresh) = checked(
        "POST /v1/auth/refresh with rotated refresh token",
        tokens.refresh(refreshed_refresh).await,
    )?;
    checked(
        "DELETE /v1/auth/logout",
        tokens.logout(rotated_access.clone()).await,
    )?;
    expect_error(
        "Logout revokes the access token",
        account.get_info(rotated_access).await,
    )?;

    let login_flow = checked(
        "LoginWithPasstotpClient::step1",
        login.step1(username.clone(), &master_key).await,
    )?;
    require(
        "Login flow exposes its operation ID",
        !login_flow.operation_id().is_empty(),
    )?;
    let (mut access_token, _) = checked(
        "LoginWithPasstotpClient::step2",
        login
            .step2(login_flow, totp.generate_current().to_string())
            .await,
    )?;
    let registration_1 = checked(
        "POST /v1/security/manage-passkeys/add/step1 (softpasskey 1)",
        security.add_passkey_step1(access_token.clone()).await,
    )?;
    let registration_credential_1 = checked(
        "SoftPasskey creates registration credential 1",
        make_registration_credential(
            &mut authenticator,
            &registration_1.passkey_props_json,
            &origin,
        ),
    )?;
    checked(
        "POST /v1/security/manage-passkeys/add/step2 (softpasskey 1)",
        security
            .add_passkey_step2(
                access_token.clone(),
                registration_1.operation_id,
                "e2e-softpasskey-1".to_owned(),
                registration_credential_1,
            )
            .await,
    )?;

    let registration_2 = checked(
        "POST /v1/security/manage-passkeys/add/step1 (softpasskey 2)",
        security.add_passkey_step1(access_token.clone()).await,
    )?;
    let registration_credential_2 = checked(
        "SoftPasskey creates registration credential 2",
        make_registration_credential(
            &mut authenticator,
            &registration_2.passkey_props_json,
            &origin,
        ),
    )?;
    checked(
        "POST /v1/security/manage-passkeys/add/step2 (softpasskey 2)",
        security
            .add_passkey_step2(
                access_token.clone(),
                registration_2.operation_id,
                "e2e-softpasskey-2".to_owned(),
                registration_credential_2,
            )
            .await,
    )?;
    let passkeys = checked(
        "GET /v1/security/passkeys after registration",
        security.get_passkeys(access_token.clone()).await,
    )?;
    require("Two SoftPasskey credentials registered", passkeys.len() == 2)?;

    let passkey_challenge = checked(
        "POST /v1/auth/login/with-passkey/step1",
        passkey_login.step1(username.clone()).await,
    )?;
    let passkey_assertion = checked(
        "SoftPasskey signs passkey-login assertion",
        make_assertion_credential(
            &mut authenticator,
            &passkey_challenge.passkey_props_json,
            &origin,
        ),
    )?;
    let (passkey_access, _) = checked(
        "POST /v1/auth/login/with-passkey/step2",
        passkey_login
            .step2(passkey_challenge.operation_id, passkey_assertion)
            .await,
    )?;
    access_token = passkey_access;
    let info_after_passkey_login = checked(
        "GET /v1/account using passkey-issued token",
        account.get_info(access_token.clone()).await,
    )?;
    require(
        "Passkey login resolved the correct account",
        info_after_passkey_login.username == username,
    )?;

    let new_password_totp = format!("{password}-changed-totp");
    let new_master_totp = new_master_key(&new_password_totp, &username)?;
    let mut password_change = checked(
        "POST /v1/security/changes/change-password/with-totp/step1",
        security
            .change_password_with_totp_step1(
                access_token.clone(),
                &master_key,
                &new_master_totp,
            )
            .await,
    )?;
    require(
        "TOTP password-change session exposes its operation ID",
        !password_change.operation_id().is_empty(),
    )?;
    checked(
        "PUT /v1/security/changes/change-password/with-totp/step2",
        security
            .change_password_with_totp_step2(
                access_token.clone(),
                &mut password_change,
                totp.generate_current().to_string(),
            )
            .await,
    )?;
    master_key = new_master_totp;
    let (relogin_access, _) = checked(
        "TOTP login with the changed password",
        async {
            let flow = login.step1(username.clone(), &master_key).await?;
            login.step2(flow, totp.generate_current().to_string()).await
        }
        .await,
    )?;
    access_token = relogin_access;

    let mut totp_change_password = checked(
        "POST /v1/security/changes/change-totp/with-password/step1",
        security
            .change_totp_with_password_step1(access_token.clone(), &master_key)
            .await,
    )?;
    require(
        "TOTP-change session exposes its operation ID",
        !totp_change_password.operation_id().is_empty(),
    )?;
    let new_totp_password = checked(
        "Parse replacement TOTP URI (password flow)",
        totp_from_url(totp_change_password.totp_url()),
    )?;
    checked(
        "PUT /v1/security/changes/change-totp/with-password/step2",
        security
            .change_totp_with_password_step2(
                access_token.clone(),
                &mut totp_change_password,
                new_totp_password.generate_current().to_string(),
            )
            .await,
    )?;
    totp = new_totp_password;
    let (totp_changed_access, _) = checked(
        "TOTP login after replacing the TOTP secret",
        async {
            let flow = login.step1(username.clone(), &master_key).await?;
            login.step2(flow, totp.generate_current().to_string()).await
        }
        .await,
    )?;
    access_token = totp_changed_access;

    let totp_challenge = checked(
        "POST /v1/security/changes/change-totp/with-passkey/step1",
        security
            .change_totp_with_passkey_step1(access_token.clone())
            .await,
    )?;
    let totp_passkey_props = totp_challenge
        .passkey_props_json
        .ok_or_else(|| io::Error::other("TOTP passkey change omitted assertion options"))?;
    let totp_assertion = checked(
        "SoftPasskey signs TOTP-change assertion",
        make_assertion_credential(&mut authenticator, &totp_passkey_props, &origin),
    )?;
    let passkey_replacement_totp = checked(
        "Parse replacement TOTP URI (passkey flow)",
        totp_from_url(totp_challenge.totp_url),
    )?;
    checked(
        "PUT /v1/security/changes/change-totp/with-passkey/step2",
        security
            .change_totp_with_passkey_step2(
                access_token.clone(),
                totp_challenge.operation_id,
                totp_assertion,
                passkey_replacement_totp.generate_current().to_string(),
            )
            .await,
    )?;
    totp = passkey_replacement_totp;

    let new_password_passkey = format!("{password}-changed-passkey");
    let new_master_passkey = new_master_key(&new_password_passkey, &username)?;
    let mut passkey_password_change = checked(
        "POST /v1/security/changes/change-password/with-passkey/step1",
        security
            .change_password_with_passkey_step1(access_token.clone(), &new_master_passkey)
            .await,
    )?;
    require(
        "Passkey password-change session exposes its operation ID",
        !passkey_password_change.operation_id().is_empty(),
    )?;
    let password_change_assertion = checked(
        "SoftPasskey signs password-change assertion",
        make_assertion_credential(
            &mut authenticator,
            &passkey_password_change.passkey_props_json(),
            &origin,
        ),
    )?;
    checked(
        "PUT /v1/security/changes/change-password/with-passkey/step2",
        security
            .change_password_with_passkey_step2(
                access_token.clone(),
                &mut passkey_password_change,
                password_change_assertion,
            )
            .await,
    )?;
    master_key = new_master_passkey;

    let (current_access, _) = checked(
        "TOTP login after both password changes",
        async {
            let flow = login.step1(username.clone(), &master_key).await?;
            login.step2(flow, totp.generate_current().to_string()).await
        }
        .await,
    )?;
    access_token = current_access;

    let latest_events = checked(
        "GET /v1/security/events after mutations",
        security.get_events(access_token.clone(), 100, 0).await,
    )?;
    expect_error(
        "Security event pagination rejects an invalid limit",
        security.get_events(access_token.clone(), 0, 0).await,
    )?;
    require(
        "Security event history includes SDK test activity",
        latest_events.len() >= 2,
    )?;

    let passkey_to_delete = checked(
        "POST /v1/security/manage-passkeys/delete/step1",
        security
            .delete_passkey_step1(access_token.clone(), passkeys[0].credential_id.clone())
            .await,
    )?;
    let delete_assertion = checked(
        "SoftPasskey signs delete-passkey assertion",
        make_assertion_credential(
            &mut authenticator,
            &passkey_to_delete.passkey_props_json,
            &origin,
        ),
    )?;
    checked(
        "DELETE /v1/security/manage-passkeys/delete/step2",
        security
            .delete_passkey_step2(
                access_token.clone(),
                passkey_to_delete.operation_id,
                passkey_to_delete.credential_id,
                delete_assertion,
            )
            .await,
    )?;
    let remaining_passkeys = checked(
        "GET /v1/security/passkeys after deletion",
        security.get_passkeys(access_token.clone()).await,
    )?;
    require("Exactly one SoftPasskey remains", remaining_passkeys.len() == 1)?;

    let passkey_challenge = checked(
        "POST /v1/auth/login/with-passkey/step1 after deleting one credential",
        passkey_login.step1(username.clone()).await,
    )?;
    let passkey_assertion = checked(
        "SoftPasskey signs assertion with remaining credential",
        make_assertion_credential(
            &mut authenticator,
            &passkey_challenge.passkey_props_json,
            &origin,
        ),
    )?;
    let (delete_access, _) = checked(
        "POST /v1/auth/login/with-passkey/step2 after deletion",
        passkey_login
            .step2(passkey_challenge.operation_id, passkey_assertion)
            .await,
    )?;
    access_token = delete_access;

    let delete_account_challenge = checked(
        "POST /v1/account/delete/with-passkey/step1",
        account.delete_with_passkey_step1(access_token.clone()).await,
    )?;
    let delete_account_assertion = checked(
        "SoftPasskey signs account-deletion assertion",
        make_assertion_credential(
            &mut authenticator,
            &delete_account_challenge.passkey_props_json,
            &origin,
        ),
    )?;
    checked(
        "DELETE /v1/account/delete/with-passkey/step2",
        account
            .delete_with_passkey_step2(
                access_token.clone(),
                delete_account_challenge.operation_id,
                delete_account_assertion,
            )
            .await,
    )?;
    expect_error(
        "Deleted account token is rejected",
        account.get_info(access_token).await,
    )?;

    let second_master_key = new_master_key(&password, &totp_username)?;
    let second_registration_flow = checked(
        "Second disposable account registration step1",
        registration
            .step1(totp_username.clone(), &second_master_key)
            .await,
    )?;
    let second_totp = checked(
        "Parse second account TOTP URI",
        totp_from_url(second_registration_flow.totp_url()),
    )?;
    let (second_access, _) = checked(
        "Second disposable account registration step2",
        registration
            .step2(
                second_registration_flow,
                second_totp.generate_current().to_string(),
            )
            .await,
    )?;
    let mut account_deletion = checked(
        "POST /v1/account/delete/with-passtotp/step1",
        account
            .delete_with_passtotp_step1(second_access.clone(), &second_master_key)
            .await,
    )?;
    require(
        "Account deletion session exposes its operation ID",
        !account_deletion.operation_id().is_empty(),
    )?;
    checked(
        "DELETE /v1/account/delete/with-passtotp/step2",
        account
            .delete_with_passtotp_step2(
                second_access,
                &mut account_deletion,
                second_totp.generate_current().to_string(),
            )
            .await,
    )?;

    println!("[ DONE ] {} checks passed", PASSED.load(Ordering::Relaxed));
    println!("Both disposable test accounts were deleted.");
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("[ E2E FAILED ] {error}");
        std::process::exit(1);
    }
}
