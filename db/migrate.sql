-- =============================================================================
-- migrate.sql — Vault Schema Migration v2
-- Run ONCE on the live vault_db BEFORE deploying the updated bridge service.
--
-- Changes:
--   1. transaction_ledger.from_user    → DROP NOT NULL  (MINTING has no sender)
--   2. transaction_ledger.transaction_type → NEW column VARCHAR(20)
--   3. chk_minting_from_user           → NEW cross-column constraint
--   4. idx_ledger_type                 → NEW index on transaction_type
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Allow from_user to be NULL.
--    MINTING entries have no sender — money originates from the system.
--    PostgreSQL FK constraints correctly allow NULL values, so existing rows
--    with a non-NULL from_user continue to satisfy the FK unchanged.
-- ---------------------------------------------------------------------------
ALTER TABLE transaction_ledger
    ALTER COLUMN from_user DROP NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. Add transaction_type column.
--    DEFAULT 'TRANSFER' backfills every existing row correctly — no
--    separate UPDATE needed.
-- ---------------------------------------------------------------------------
ALTER TABLE transaction_ledger
    ADD COLUMN IF NOT EXISTS transaction_type VARCHAR(20)
        NOT NULL
        DEFAULT 'TRANSFER'
        CHECK (transaction_type IN ('TRANSFER', 'MINTING', 'REFUND'));

-- ---------------------------------------------------------------------------
-- 3. Cross-column integrity:
--    • MINTING rows   → from_user MUST be NULL   (no sender)
--    • All other rows → from_user MUST NOT be NULL (real sender required)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname  = 'chk_minting_from_user'
          AND  conrelid = 'transaction_ledger'::regclass
    ) THEN
        ALTER TABLE transaction_ledger
            ADD CONSTRAINT chk_minting_from_user
            CHECK (
                (transaction_type = 'MINTING'  AND from_user IS NULL)
                OR
                (transaction_type <> 'MINTING' AND from_user IS NOT NULL)
            );
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Index on transaction_type — efficient for audit/admin queries.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ledger_type
    ON transaction_ledger(transaction_type);

COMMIT;

-- ---------------------------------------------------------------------------
-- Verification — prints the final column list of transaction_ledger.
-- ---------------------------------------------------------------------------
SELECT
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'transaction_ledger'
ORDER BY ordinal_position;
