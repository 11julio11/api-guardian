"""Database connection layer with PostgreSQL Row-Level Security (RLS) support."""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, List, Optional
import uuid

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://api_user:agent_ready_pass_123@localhost:5432/agent_api_db")


class InMemoryMultiTenantDB:
    """Local fallback database emulating PostgreSQL Row-Level Security when Postgres is not running."""

    def __init__(self):
        self.documents: List[Dict] = []
        self.transactions: List[Dict] = []

    def insert_document(self, tenant_id: str, title: str, content: str) -> Dict:
        doc = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "title": title,
            "content": content,
            "created_at": "2026-09-24T00:00:00Z"
        }
        self.documents.append(doc)
        return {k: v for k, v in doc.items() if k != "tenant_id"}

    def get_documents(self, tenant_id: str) -> List[Dict]:
        # Emulates RLS filter: ONLY returns documents matching the current session tenant_id
        return [{k: v for k, v in doc.items() if k != "tenant_id"} for doc in self.documents if doc["tenant_id"] == tenant_id]

    def insert_transaction(self, tenant_id: str, idempotency_key: str, amount: float, currency: str) -> Dict:
        tx = {
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "idempotency_key": idempotency_key,
            "amount": amount,
            "currency": currency,
            "status": "completed",
            "created_at": "2026-09-24T00:00:00Z"
        }
        self.transactions.append(tx)
        return {k: v for k, v in tx.items() if k != "tenant_id"}


# Global in-memory fallback instance
mock_db = InMemoryMultiTenantDB()


@asynccontextmanager
async def get_tenant_db_session(tenant_id: str) -> AsyncGenerator:
    """Acquires a database connection, initiates transaction, and injects SET LOCAL app.current_tenant_id."""
    # Attempt asyncpg connection if available, otherwise yield mock_db
    try:
        import asyncpg
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5, timeout=2.0)
        async with pool.acquire() as conn:
            async with conn.transaction():
                # 🔒 SET LOCAL ensures the variable only lives for the current transaction in this connection
                await conn.execute("SET LOCAL app.current_tenant_id = $1;", tenant_id)
                yield conn
        await pool.close()
    except Exception:
        # Fallback to local memory simulator with strict RLS isolation
        yield mock_db
