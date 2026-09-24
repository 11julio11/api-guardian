-- ==============================================================================
-- 🛡️ Agent-Ready Multi-Tenant PostgreSQL Schema with Row-Level Security (RLS)
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Tenants & Organizations
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'standard',
    created_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- 2. Multi-Tenant Resources (ej: Documents / Knowledge Base)
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT clock_timestamp()
);

-- 3. Idempotent Financial/Transactional Records
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT clock_timestamp(),
    CONSTRAINT uq_tenant_idempotency UNIQUE (tenant_id, idempotency_key)
);

-- ==============================================================================
-- ⚡ ÍNDICES CRÍTICOS PARA EL OPTIMIZADOR CON RLS
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_docs_tenant_created ON documents (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trans_tenant_created ON transactions (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trans_idemp ON transactions (tenant_id, idempotency_key);

-- ==============================================================================
-- 🔒 POLÍTICAS DE ROW-LEVEL SECURITY (RLS)
-- ==============================================================================
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;

-- Política estricta para documents: Lectura, inserción, actualización y borrado
DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
CREATE POLICY tenant_isolation_documents ON documents
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
    );

-- Política estricta para transactions
DROP POLICY IF EXISTS tenant_isolation_transactions ON transactions;
CREATE POLICY tenant_isolation_transactions ON transactions
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID
    );

-- ==============================================================================
-- 👤 ROL DE APLICACIÓN RESTRINGIDO (SIN BYPASSRLS)
-- ==============================================================================
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'api_user') THEN
        CREATE ROLE api_user WITH LOGIN PASSWORD 'agent_ready_pass_123';
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO api_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO api_user;

-- Datos de prueba para dos organizaciones distintas
INSERT INTO tenants (id, name, plan) VALUES
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'Empresa Alfa S.A.', 'enterprise'),
    ('b1ffcd88-8b1a-3de7-aa5c-5aa8ac271b22', 'Startup Beta Dev', 'starter')
ON CONFLICT (id) DO NOTHING;
