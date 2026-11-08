
-- ============================================================================
-- Migration: initdb
-- Created:   2026-10-21T20:50:00Z
-- ============================================================================

BEGIN;

-- ============================================================================
-- Types
-- ============================================================================

-- Security and account events.
-- Events prefixed with "sudo_" require successful confirmation of the action.
CREATE TYPE EVENTS AS ENUM (
    -- Account lifecycle
    'sudo_account_created',
    'sudo_account_deleted_with_passkey',
    'sudo_account_deleted_with_passtotp',
    'sudo_account_delete_failed_with_passkey',
    'sudo_account_delete_failed_with_passtotp',

    -- Authentication
    'login_with_passkey',
    'login_with_passtotp',
    'login_failed_with_passkey',
    'login_failed_with_passtotp',
    'logout',
    'token_refresh',

    -- Password management
    'sudo_password_updated_with_passkey',
    'sudo_password_updated_with_totp',
    'sudo_password_update_failed_with_passkey',
    'sudo_password_update_failed_with_totp',

    -- TOTP management
    'sudo_totp_updated_with_passkey',
    'sudo_totp_updated_with_password',
    'sudo_totp_update_failed_with_passkey',
    'sudo_totp_update_failed_with_password',

    -- Passkey management
    'sudo_passkey_registered_with_totp',
    'sudo_passkey_registered_with_password',
    'sudo_passkey_deleted_with_totp',
    'sudo_passkey_deleted_with_password',
    'sudo_passkey_register_failed_with_totp',
    'sudo_passkey_register_failed_with_password',
    'sudo_passkey_delete_failed_with_totp',
    'sudo_passkey_delete_failed_with_password',

    -- Encrypted vault
    'blob_created',
    'blob_updated',
    'blob_accessed'
);

-- ============================================================================
-- Tables
-- ============================================================================

-- Users
CREATE TABLE users (
    username    TEXT        PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OPAQUE credentials
CREATE TABLE user_opaque (
    username    TEXT        PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    password    BYTEA       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- TOTP configuration
CREATE TABLE user_totp (
    username    TEXT        PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    totp        BYTEA       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- WebAuthn passkeys
CREATE TABLE user_passkeys (
    username       TEXT        NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    credential_id  BYTEA       PRIMARY KEY,
    keyname        TEXT        NOT NULL,
    passkey        JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Encrypted vault metadata
CREATE TABLE user_blob (
    username      TEXT        PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
    hash_blake3   BYTEA       NOT NULL,
    version       BIGINT      NOT NULL CHECK (version >= 0),
    size          BIGINT      NOT NULL CHECK (size >= 0),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT user_blob_hash_blake3_length CHECK (OCTET_LENGTH(hash_blake3) = 32)
);

-- Security event log
CREATE TABLE user_events (
    username      TEXT        NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    id            UUID        PRIMARY KEY,
    event_type    EVENTS      NOT NULL,
    ip_address    INET,
    user_agent    TEXT,
    event_text    TEXT,
    trace_id      UUID,
    operation_id  UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Triggers
-- ============================================================================

-- Automatically refresh updated_at on every UPDATE.
CREATE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_user_opaque_updated_at
BEFORE UPDATE ON user_opaque
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_user_totp_updated_at
BEFORE UPDATE ON user_totp
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_user_blob_updated_at
BEFORE UPDATE ON user_blob
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ============================================================================
-- Indexes
-- ============================================================================

-- Passkeys: list a user's keys.
CREATE INDEX idx_user_passkeys_username
    ON user_passkeys (username);

-- Passkeys: list a user's keys by creation time.
CREATE INDEX idx_user_passkeys_username_created_at
    ON user_passkeys (username, created_at DESC);

-- Events: a user's timeline.
CREATE INDEX idx_user_events_username_created_at
    ON user_events (username, created_at DESC);

-- Events: a user's timeline filtered by event type.
CREATE INDEX idx_user_events_username_type_created_at
    ON user_events (username, event_type, created_at DESC);

-- Events: global timeline.
CREATE INDEX idx_user_events_created_at
    ON user_events (created_at DESC);

-- Events: lookup by request trace ID.
CREATE INDEX idx_user_events_trace_id
    ON user_events (trace_id)
    WHERE trace_id IS NOT NULL;

-- Events: lookup by operation ID.
CREATE INDEX idx_user_events_operation_id
    ON user_events (operation_id)
    WHERE operation_id IS NOT NULL;

-- Events: timeline filtered by event type.
CREATE INDEX idx_user_events_event_type_created_at
    ON user_events (event_type, created_at DESC);

COMMIT;
