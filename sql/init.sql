-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Acme - internal ACME certificate authority server.
-- Sentin8:Acme stores CA keys, accounts, orders, and certificates on the
-- local filesystem. Its only database table is the DBX producer outbox
-- (RS §3 D1): acme events ride the local-outbox + Bus produce-API path
-- like every other producer - no direct `bus.inbox` writes, no producer
-- grants on Bus's internal durability tables (architecture-principles
-- §6.7). The shell-style relay (spawned in server.rs) drains this table
-- post-commit with retry + backoff.

CREATE SCHEMA IF NOT EXISTS acme;

-- Outbox DDL + NOTIFY trigger (sentin8-outbox::outbox_table_sql, applied
-- verbatim here because acme boots custom, not via the shell):
CREATE TABLE IF NOT EXISTS acme.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
    ON acme.outbox (created_at) WHERE relayed = false;
ALTER TABLE acme.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON acme.outbox;
CREATE POLICY outbox_select ON acme.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON acme.outbox;
CREATE POLICY outbox_insert ON acme.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON acme.outbox;
CREATE POLICY outbox_update ON acme.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION acme.acme_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('acme_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON acme.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON acme.outbox
    FOR EACH ROW
    EXECUTE FUNCTION acme.acme_notify_outbox();

-- ── Grants (service-owned - applied with this schema's migration) ──
-- Acme's own role: DML on its own outbox (the relay drains + retries).
GRANT USAGE ON SCHEMA acme TO sentin8_acme_service;
GRANT SELECT, INSERT, UPDATE ON acme.outbox TO sentin8_acme_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA acme TO sentin8_acme_service;