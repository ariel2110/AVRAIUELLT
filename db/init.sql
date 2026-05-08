-- =============================================================================
-- Vault Database Initialization Script
-- init.sql
--
-- Runs once on first container boot (empty data directory).
-- Establishes all tables, indexes, constraints, and audit triggers
-- for the Taz currency Vault.
-- =============================================================================

-- Enable the pgcrypto extension for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE: users_taz_balance
-- The canonical record of every user's Taz holdings.
--
-- balance can be negative when a user draws on their credit_limit.
-- The application layer enforces: balance + credit_limit >= transfer_amount.
-- We intentionally do NOT add CHECK (balance >= 0) here because credit
-- facilities legitimately allow the balance to go below zero.
-- =============================================================================
CREATE TABLE IF NOT EXISTS users_taz_balance (
    user_id      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    balance      NUMERIC(20,6) NOT NULL DEFAULT 0,
    credit_limit NUMERIC(20,6) NOT NULL DEFAULT 0
                               CHECK (credit_limit >= 0),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  users_taz_balance              IS 'Canonical Taz balance per user.';
COMMENT ON COLUMN users_taz_balance.user_id      IS 'Matches the user_id from the central User service.';
COMMENT ON COLUMN users_taz_balance.balance      IS 'Current balance in Taz. May be negative within credit_limit.';
COMMENT ON COLUMN users_taz_balance.credit_limit IS 'Maximum amount the user may overdraw. Always >= 0.';
COMMENT ON COLUMN users_taz_balance.updated_at   IS 'Timestamp of the last balance modification.';

-- =============================================================================
-- TABLE: transaction_ledger
-- Immutable append-only record of every attempted Taz transfer.
-- Completed and failed transactions are both recorded for full auditability.
--
-- transaction_type values:
--   TRANSFER — peer-to-peer Taz transfer (from_user required)
--   MINTING  — system issuance of new Taz into the Treasury (from_user NULL)
--   REFUND   — reversal/refund of a prior transfer (from_user required)
-- =============================================================================
CREATE TABLE IF NOT EXISTS transaction_ledger (
    transaction_id   UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user        UUID                       -- NULL for MINTING
                                   REFERENCES users_taz_balance(user_id),
    to_user          UUID          NOT NULL
                                   REFERENCES users_taz_balance(user_id),
    amount           NUMERIC(20,6) NOT NULL
                                   CHECK (amount > 0),
    status           VARCHAR(20)   NOT NULL
                                   CHECK (status IN ('completed', 'failed', 'pending')),
    transaction_type VARCHAR(20)   NOT NULL
                                   DEFAULT 'TRANSFER'
                                   CHECK (transaction_type IN ('TRANSFER', 'MINTING', 'REFUND')),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    -- MINTING rows must have no sender; all other rows must have one.
    CONSTRAINT chk_minting_from_user CHECK (
        (transaction_type = 'MINTING'  AND from_user IS NULL)
        OR
        (transaction_type <> 'MINTING' AND from_user IS NOT NULL)
    )
);

COMMENT ON TABLE  transaction_ledger                      IS 'Immutable ledger of all Taz transfers.';
COMMENT ON COLUMN transaction_ledger.transaction_id       IS 'Globally unique ID for this transfer event.';
COMMENT ON COLUMN transaction_ledger.from_user            IS 'Sender user_id (FK → users_taz_balance). NULL for MINTING.';
COMMENT ON COLUMN transaction_ledger.to_user              IS 'Recipient user_id (FK → users_taz_balance).';
COMMENT ON COLUMN transaction_ledger.amount               IS 'Amount of Taz transferred. Always positive.';
COMMENT ON COLUMN transaction_ledger.status               IS 'completed | failed | pending';
COMMENT ON COLUMN transaction_ledger.transaction_type     IS 'TRANSFER | MINTING | REFUND';
COMMENT ON COLUMN transaction_ledger.created_at           IS 'Timestamp when the transfer was attempted.';

-- Performance indexes for common query patterns.
CREATE INDEX IF NOT EXISTS idx_ledger_from_user  ON transaction_ledger(from_user);
CREATE INDEX IF NOT EXISTS idx_ledger_to_user    ON transaction_ledger(to_user);
CREATE INDEX IF NOT EXISTS idx_ledger_created_at ON transaction_ledger(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_status     ON transaction_ledger(status);
CREATE INDEX IF NOT EXISTS idx_ledger_type       ON transaction_ledger(transaction_type);

-- =============================================================================
-- TABLE: balance_audit_log
-- Automatically populated by the trigger below.
-- Records every change to a user's balance with before/after values.
-- This table is written by the database itself — not by the application.
-- =============================================================================
CREATE TABLE IF NOT EXISTS balance_audit_log (
    audit_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL,
    old_balance  NUMERIC(20,6),
    new_balance  NUMERIC(20,6) NOT NULL,
    changed_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  balance_audit_log              IS 'Auto-populated audit trail for every balance change.';
COMMENT ON COLUMN balance_audit_log.old_balance  IS 'Balance before the update (NULL on first insert).';
COMMENT ON COLUMN balance_audit_log.new_balance  IS 'Balance after the update.';
COMMENT ON COLUMN balance_audit_log.changed_at   IS 'Exact timestamp of the database-level change.';

CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON balance_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_changed_at ON balance_audit_log(changed_at DESC);

-- =============================================================================
-- TRIGGER FUNCTION: fn_audit_balance_change
-- Fires AFTER INSERT OR UPDATE on users_taz_balance.
-- Writes the old and new balance into balance_audit_log automatically.
-- The application layer never writes to balance_audit_log directly.
-- =============================================================================
CREATE OR REPLACE FUNCTION fn_audit_balance_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO balance_audit_log (user_id, old_balance, new_balance, changed_at)
    VALUES (
        NEW.user_id,
        -- OLD is NULL on INSERT (no previous row)
        CASE WHEN TG_OP = 'UPDATE' THEN OLD.balance ELSE NULL END,
        NEW.balance,
        NOW()
    );
    RETURN NEW;
END;
$$;

-- Attach trigger to users_taz_balance for both INSERT and UPDATE operations.
DROP TRIGGER IF EXISTS trg_audit_balance ON users_taz_balance;
CREATE TRIGGER trg_audit_balance
    AFTER INSERT OR UPDATE ON users_taz_balance
    FOR EACH ROW
    EXECUTE FUNCTION fn_audit_balance_change();

-- =============================================================================
-- FUNCTION: fn_update_balance_timestamp
-- Automatically keeps updated_at current on every balance update.
-- =============================================================================
CREATE OR REPLACE FUNCTION fn_update_balance_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_update_balance_timestamp ON users_taz_balance;
CREATE TRIGGER trg_update_balance_timestamp
    BEFORE UPDATE ON users_taz_balance
    FOR EACH ROW
    EXECUTE FUNCTION fn_update_balance_timestamp();
