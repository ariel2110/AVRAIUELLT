"""
vault/bridge/main.py
====================
Vault Bridge — Internal FastAPI service for the Taz currency Vault.

SECURITY ARCHITECTURE:
  - Zero-trust: every endpoint (except /health) requires a valid
    X-Vault-Internal-Key header.  Keys are checked with hmac.compare_digest
    to prevent timing-based side-channel attacks.
  - Token rotation: VAULT_INTERNAL_KEYS accepts a comma-separated list of
    valid keys, enabling zero-downtime key rotation.
  - Admin endpoints require X-Vault-Admin-Key (separate key set loaded from
    VAULT_ADMIN_KEYS env var).  Admin keys are never accepted on regular
    endpoints, and regular keys are never accepted on admin endpoints.
  - Treasury enforcement: POST /admin/mint only mints into TREASURY_WALLET_ID
    (a fixed UUID from env).  Minting to any other wallet is rejected 403.
  - Rate limiting: per-IP limits via slowapi (in-memory, no Redis required
    for this internal single-instance service).
  - No public introspection: Swagger UI, ReDoc, and the OpenAPI schema
    endpoint are all disabled.
  - Structured request logging with all auth headers masked as ***MASKED***
    so secrets never appear in logs.
  - ACID transfers with SELECT FOR UPDATE and deadlock-safe row locking
    (consistent UUID sort order before acquiring locks).
  - Non-root process: the Dockerfile runs this as uid 1001 (vault).
"""

import asyncio
import hashlib
import base64
import hmac
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal, ROUND_HALF_UP
from typing import Annotated, Any
from uuid import UUID

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

DATABASE_URL: str = os.environ["DATABASE_URL"]

# Build a set of SHA-256 hashes of the valid vault keys.
# We store hashes (not plaintext) in memory so that a heap dump or core file
# never exposes the raw secret tokens.
_RAW_KEYS: list[str] = [
    k.strip() for k in os.environ["VAULT_INTERNAL_KEYS"].split(",") if k.strip()
]
if not _RAW_KEYS:
    raise RuntimeError("VAULT_INTERNAL_KEYS must contain at least one key.")

VAULT_KEY_HASHES: set[str] = {
    hashlib.sha256(k.encode()).hexdigest() for k in _RAW_KEYS
}
del _RAW_KEYS  # Remove plaintext keys from memory immediately after hashing.

# Admin keys — required for privileged endpoints (e.g. POST /admin/mint).
_RAW_ADMIN_KEYS: list[str] = [
    k.strip() for k in os.environ["VAULT_ADMIN_KEYS"].split(",") if k.strip()
]
if not _RAW_ADMIN_KEYS:
    raise RuntimeError("VAULT_ADMIN_KEYS must contain at least one key.")

ADMIN_KEY_HASHES: set[str] = {
    hashlib.sha256(k.encode()).hexdigest() for k in _RAW_ADMIN_KEYS
}
del _RAW_ADMIN_KEYS

# Treasury wallet — the only wallet that may receive minted Taz.
TREASURY_WALLET_ID: str = os.environ["TREASURY_WALLET_ID"].strip()
if not TREASURY_WALLET_ID:
    raise RuntimeError("TREASURY_WALLET_ID must be set in environment.")

# ---------------------------------------------------------------------------
# Escrow / fee / notification configuration
# ---------------------------------------------------------------------------

# Platform-owned escrow wallet — holds buyer funds until delivery confirmed.
ESCROW_WALLET_ID: str = os.environ.get("ESCROW_WALLET_ID", "").strip()

# TAZO platform fee percentage (e.g. "15" = 15%).  Driver receives the rest.
_CENT = Decimal("0.01")
TAZO_FEE_PCT: Decimal = Decimal(os.environ.get("TAZO_FEE_PCT", "15"))
WELCOME_BONUS_TAZ: Decimal = Decimal(os.environ.get("WELCOME_BONUS_TAZ", "30"))

# Twilio SMS — admin notifications on high-value or failed transactions.
TWILIO_ACCOUNT_SID: str  = os.environ.get("TWILIO_ACCOUNT_SID",  "").strip()
TWILIO_AUTH_TOKEN:  str  = os.environ.get("TWILIO_AUTH_TOKEN",   "").strip()
TWILIO_FROM_PHONE:  str  = os.environ.get("TWILIO_FROM_PHONE",   "").strip()
TAZO_ADMIN_PHONE:   str  = os.environ.get("TAZO_ADMIN_PHONE",    "").strip()
SMS_THRESHOLD_NIS:  Decimal = Decimal(os.environ.get("SMS_THRESHOLD_NIS", "200"))

# Tazo-Go webhook — Vault fires payment.locked after a successful escrow lock.
TAZO_GO_WEBHOOK_URL:  str = os.environ.get("TAZO_GO_WEBHOOK_URL",  "").strip()
TAZO_GO_INTERNAL_KEY: str = os.environ.get("TAZO_GO_INTERNAL_KEY", "").strip()

# ---------------------------------------------------------------------------
# Logging — structured, minimal
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("vault.bridge")

# ---------------------------------------------------------------------------
# Async helpers — Twilio SMS + Tazo-Go webhook
# ---------------------------------------------------------------------------

async def _sms_admin(message: str) -> None:
    """
    Fire-and-forget SMS to TAZO_ADMIN_PHONE via Twilio REST API.

    Silently skips if any Twilio credential is absent so the Vault works
    without Twilio configured (development / staging).
    """
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_PHONE, TAZO_ADMIN_PHONE]):
        return
    import httpx
    url = (
        f"https://api.twilio.com/2010-04-01/Accounts"
        f"/{TWILIO_ACCOUNT_SID}/Messages.json"
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
                data={
                    "From": TWILIO_FROM_PHONE,
                    "To":   TAZO_ADMIN_PHONE,
                    "Body": message[:1600],
                },
            )
        if resp.status_code not in (200, 201):
            logger.warning("Twilio SMS HTTP %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Twilio SMS failed: %s", exc)


async def _fire_payment_locked_webhook(
    order_id: str,
    vault_tx_id: str,
    amount: Decimal,
    buyer_wallet_id: str,
) -> None:
    """
    Notify Tazo-Go that an escrow lock succeeded so it can auto-dispatch.
    Called inside the /escrow/lock handler after a successful DB commit.
    Fire-and-forget — Vault does not block on Tazo-Go's response.

    Retries transient failures (network errors, 5xx, 429) with exponential
    backoff. Does not retry on other 4xx (client errors).
    """
    if not TAZO_GO_WEBHOOK_URL or not TAZO_GO_INTERNAL_KEY:
        return
    import httpx

    target = f"{TAZO_GO_WEBHOOK_URL.rstrip('/')}/webhooks/payment-locked"
    payload = {
        "order_id": order_id,
        "vault_tx_id": vault_tx_id,
        "amount": str(amount),
        "buyer_wallet_id": buyer_wallet_id,
    }
    headers = {
        "x-internal-key": TAZO_GO_INTERNAL_KEY,
        "Idempotency-Key": vault_tx_id,
    }
    max_attempts = 3
    base_delay_s = 0.5

    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(target, headers=headers, json=payload)
            if resp.status_code in (200, 201):
                logger.info("payment.locked webhook fired — order=%s", order_id)
                return
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                logger.warning(
                    "payment.locked webhook → Tazo-Go returned %s (no retry): %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return
            logger.warning(
                "payment.locked webhook attempt %s/%s → HTTP %s: %s",
                attempt,
                max_attempts,
                resp.status_code,
                resp.text[:200],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "payment.locked webhook attempt %s/%s failed: %s",
                attempt,
                max_attempts,
                exc,
            )
        if attempt < max_attempts:
            await asyncio.sleep(base_delay_s * (2 ** (attempt - 1)))
    logger.warning(
        "payment.locked webhook exhausted retries — order=%s vault_tx=%s",
        order_id,
        vault_tx_id,
    )

# ---------------------------------------------------------------------------
# Database engine — SQLAlchemy 2 async with asyncpg
# ---------------------------------------------------------------------------

engine = create_async_engine(
    DATABASE_URL,
    # Pool tuning for a low-traffic internal service.
    pool_size=10,        # Persistent connections kept open.
    max_overflow=20,     # Extra connections allowed under burst load.
    pool_timeout=30,     # Seconds to wait for a connection before raising.
    pool_pre_ping=True,  # Validate connections before use (handles DB restarts).
    echo=False,          # Never log SQL — would expose amounts and user IDs.
)

AsyncSessionFactory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ---------------------------------------------------------------------------
# Rate limiter (slowapi)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# Application lifespan — clean engine disposal on shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Vault Bridge starting up.")
    yield
    await engine.dispose()
    logger.info("Vault Bridge shut down. Database connections closed.")

# ---------------------------------------------------------------------------
# FastAPI app — introspection endpoints disabled
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Vault Bridge",
    lifespan=lifespan,
    # Disable all public documentation/schema endpoints.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Protected Swagger UI — Basic Auth (user: vault, pass: VAULT_ADMIN_KEY)
# ---------------------------------------------------------------------------

_DOCS_USER = "vault"
_DOCS_PASS_HASH = hashlib.sha256(
    os.environ["VAULT_ADMIN_KEYS"].split(",")[0].strip().encode()
).hexdigest()


def _check_docs_auth(request: Request) -> None:
    """Raise 401 with WWW-Authenticate if Basic Auth is missing/wrong."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Vault Docs"'},
        )
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        user, _, password = decoded.partition(":")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid credentials",
                            headers={"WWW-Authenticate": 'Basic realm="Vault Docs"'})
    user_ok = hmac.compare_digest(user, _DOCS_USER)
    pass_ok = hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), _DOCS_PASS_HASH
    )
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials",
                            headers={"WWW-Authenticate": 'Basic realm="Vault Docs"'})


@app.get("/vault-docs", include_in_schema=False)
async def vault_docs(request: Request):
    _check_docs_auth(request)
    html = f"""
    <!DOCTYPE html><html>
    <head>
      <title>Vault Bridge — API Docs</title>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    </head>
    <body>
      <div id="swagger-ui"></div>
      <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
      <script>
        SwaggerUIBundle({{
          url: "/vault-openapi.json",
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
          layout: "BaseLayout",
          deepLinking: true,
          requestInterceptor: (req) => {{
            req.headers['X-Internal-Key'] = prompt('X-Internal-Key (leave blank to skip)') || '';
            return req;
          }}
        }})
      </script>
    </body></html>
    """
    return HTMLResponse(html)


@app.get("/vault-openapi.json", include_in_schema=False)
async def vault_openapi(request: Request):
    _check_docs_auth(request)
    return JSONResponse(get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    ))

# ---------------------------------------------------------------------------
# Middleware — structured request logging with header masking
# ---------------------------------------------------------------------------

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()

    # Mask all auth headers so they never appear in logs.
    _MASKED_HEADERS = {"x-vault-internal-key", "x-vault-admin-key"}
    masked_headers = {
        k: ("***MASKED***" if k.lower() in _MASKED_HEADERS else v)
        for k, v in request.headers.items()
    }

    response = await call_next(request)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "%s %s %s — %dms — client=%s",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        request.client.host if request.client else "unknown",
    )
    return response

# ---------------------------------------------------------------------------
# Auth dependency — zero-trust header verification
# ---------------------------------------------------------------------------

async def verify_vault_key(
    x_vault_internal_key: Annotated[str | None, Header()] = None,
) -> None:
    """
    Validates the X-Vault-Internal-Key header on every protected request.

    Security properties:
      1. hmac.compare_digest → constant-time comparison prevents timing attacks.
      2. We compare SHA-256 hashes of both the provided and the expected keys,
         so the comparison time is always identical regardless of key length.
      3. A missing header and an invalid header both return 403 (no information
         leakage about whether the endpoint exists).
    """
    if x_vault_internal_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing authentication header.",
        )

    provided_hash = hashlib.sha256(x_vault_internal_key.encode()).hexdigest()

    # Check against every stored hash in constant time.
    # We OR the results together to avoid short-circuiting.
    authenticated = False
    for stored_hash in VAULT_KEY_HASHES:
        if hmac.compare_digest(provided_hash, stored_hash):
            authenticated = True

    if not authenticated:
        logger.warning("Authentication failure from client — invalid vault key.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication credentials.",
        )

# Reusable dependency alias for cleaner endpoint signatures.
VaultAuth = Annotated[None, Depends(verify_vault_key)]

# ---------------------------------------------------------------------------
# Admin auth dependency — required for privileged operations
# ---------------------------------------------------------------------------

async def verify_admin_key(
    x_vault_admin_key: Annotated[str | None, Header()] = None,
) -> None:
    """
    Validates the X-Vault-Admin-Key header on privileged endpoints.

    Uses the same constant-time SHA-256 comparison strategy as verify_vault_key.
    Admin keys are completely separate from internal keys — a regular internal
    key will always be rejected here, and vice versa.
    """
    if x_vault_admin_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing admin authentication header.",
        )

    provided_hash = hashlib.sha256(x_vault_admin_key.encode()).hexdigest()

    authenticated = False
    for stored_hash in ADMIN_KEY_HASHES:
        if hmac.compare_digest(provided_hash, stored_hash):
            authenticated = True

    if not authenticated:
        logger.warning("Admin authentication failure from client — invalid admin key.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin authentication credentials.",
        )

AdminAuth = Annotated[None, Depends(verify_admin_key)]

# ---------------------------------------------------------------------------
# DB session dependency
# ---------------------------------------------------------------------------

async def get_db() -> AsyncSession:  # type: ignore[return]
    async with AsyncSessionFactory() as session:
        yield session

DBSession = Annotated[AsyncSession, Depends(get_db)]

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class BalanceResponse(BaseModel):
    user_id:      UUID
    balance:      Decimal
    credit_limit: Decimal
    updated_at:   Any  # datetime — returned as-is from DB


class TransactionRequest(BaseModel):
    from_user: UUID = Field(..., description="Sender's user_id.")
    to_user:   UUID = Field(..., description="Recipient's user_id.")
    amount:    Decimal = Field(..., gt=0, description="Taz to transfer. Must be > 0.")


class TransactionResponse(BaseModel):
    transaction_id: UUID
    status:         str
    from_user:      UUID
    to_user:        UUID
    amount:         Decimal


class WalletCreateRequest(BaseModel):
    user_id:       UUID    = Field(..., description="The user_id to register in the Vault. Must be the canonical UUID from the User service.")
    credit_limit:  Decimal = Field(Decimal("0"), ge=0, description="Initial credit limit in Taz. Defaults to 0.")
    welcome_bonus: bool    = Field(True, description="If True, credits WELCOME_BONUS_TAZ Taz from Treasury on wallet creation.")


class WalletCreateResponse(BaseModel):
    user_id:      UUID
    balance:      Decimal
    credit_limit: Decimal
    created_at:   Any  # TIMESTAMPTZ returned as-is from DB


class TopupRequest(BaseModel):
    wallet_id: UUID    = Field(..., description="Target wallet to credit.")
    amount:    Decimal = Field(..., gt=0, description="Amount paid in ILS (1 ILS = 1 Taz). 10% bonus auto-added.")
    reference: str     = Field("", max_length=128, description="GreenInvoice document ID or payment reference.")


class TopupResponse(BaseModel):
    topup_tx_id:    UUID
    bonus_tx_id:    UUID
    wallet_id:      UUID
    base_amount:    Decimal
    bonus_amount:   Decimal
    total_credited: Decimal
    reference:      str


class MintRequest(BaseModel):
    amount: Decimal = Field(..., gt=0, description="Amount of Taz to mint into the Treasury. Must be > 0.")
    note:   str     = Field("", max_length=255, description="Optional human-readable note for audit purposes.")


class MintResponse(BaseModel):
    transaction_id: UUID
    treasury_id:    UUID
    amount:         Decimal
    new_balance:    Decimal
    status:         str


class TransactionRecord(BaseModel):
    transaction_id:   UUID
    from_user:        UUID | None  # NULL for MINTING
    to_user:          UUID
    amount:           Decimal
    status:           str
    transaction_type: str
    created_at:       Any


class TransactionHistoryResponse(BaseModel):
    user_id:      UUID
    total:        int
    limit:        int
    offset:       int
    transactions: list[TransactionRecord]


class TransferRequest(BaseModel):
    from_user:        UUID    = Field(..., description="Sender's user_id.")
    to_user:          UUID    = Field(..., description="Recipient's user_id.")
    amount:           Decimal = Field(..., gt=0, description="Taz to transfer. Must be > 0.")
    order_id:         str | None = Field(None, max_length=128,
                          description="Optional order reference for escrow tracking.")
    transaction_type: str = Field("TRANSFER",
                          description="Ledger type tag, e.g. TRANSFER, ESCROW_LOCK, ESCROW_RELEASE, REFUND.")


class TransferResponse(BaseModel):
    transaction_id:   UUID
    status:           str
    from_user:        UUID
    to_user:          UUID
    amount:           Decimal
    order_id:         str | None
    transaction_type: str


# ---------------------------------------------------------------------------
# Escrow Pydantic models
# ---------------------------------------------------------------------------

class EscrowLockRequest(BaseModel):
    buyer_wallet_id: UUID   = Field(..., description="Buyer's Vault wallet UUID.")
    order_id:        str    = Field(..., max_length=128, description="Tazo-Web order UUID.")
    amount:          Decimal = Field(..., gt=0, description="Amount to lock in Taz.")


class EscrowLockResponse(BaseModel):
    transaction_id:  UUID
    order_id:        str
    amount:          Decimal
    escrow_wallet:   UUID
    status:          str


class EscrowReleaseRequest(BaseModel):
    order_id:         str  = Field(..., max_length=128, description="Tazo-Web order UUID.")
    driver_wallet_id: UUID = Field(..., description="Driver's Vault wallet UUID to receive payout.")
    amount:           Decimal = Field(..., gt=0, description="Full escrowed amount in Taz (pre-fee).")


class EscrowReleaseResponse(BaseModel):
    release_tx_id:  UUID
    fee_tx_id:      UUID
    order_id:       str
    driver_amount:  Decimal
    fee_amount:     Decimal
    driver_wallet:  UUID
    treasury_wallet: UUID
    status:         str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", status_code=200)
async def health_check() -> dict[str, str]:
    """
    Lightweight liveness probe. No authentication required.
    Used by Docker healthchecks and the Admin server's circuit breaker.
    """
    return {"status": "ok"}


@app.get("/balance/{user_id}", response_model=BalanceResponse)
@limiter.limit("30/minute")
async def get_balance(
    request: Request,  # Required by slowapi
    user_id: UUID,
    _auth: VaultAuth,
    db: DBSession,
) -> BalanceResponse:
    """
    Returns the current Taz balance and credit limit for a user.

    Rate limit: 30 requests/minute per calling IP.
    """
    result = await db.execute(
        text(
            "SELECT user_id, balance, credit_limit, updated_at "
            "FROM users_taz_balance "
            "WHERE user_id = :user_id"
        ),
        {"user_id": str(user_id)},
    )
    row = result.mappings().first()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found in Vault.",
        )

    return BalanceResponse(**row)


@app.post("/transaction", response_model=TransactionResponse, status_code=201)
@limiter.limit("20/minute")
async def process_transaction(
    request: Request,  # Required by slowapi
    payload: TransactionRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> TransactionResponse:
    """
    Transfers Taz from one user to another with full ACID guarantees.

    ACID & safety properties:
      - Atomicity:   The entire debit + credit + ledger insert occurs inside a
                     single database transaction.  On any failure the whole
                     operation rolls back — money is never created or destroyed.
      - Consistency: We verify the sender has sufficient (balance + credit_limit)
                     before touching any rows.
      - Isolation:   SELECT … FOR UPDATE acquires row-level locks, preventing
                     any concurrent transaction from reading stale balances.
      - Durability:  PostgreSQL WAL guarantees committed rows survive crashes.

    Deadlock prevention:
      Both user rows are locked in a consistent order (lexicographic sort of
      their UUID strings).  This means two concurrent transfers between the
      same pair of users will always acquire locks in the same order, making
      a deadlock impossible.

    Rate limit: 20 requests/minute per calling IP.
    """
    from_id = str(payload.from_user)
    to_id   = str(payload.to_user)

    if from_id == to_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="from_user and to_user must be different.",
        )

    # Consistent lock order — lexicographic sort prevents deadlocks.
    uid_a, uid_b = sorted([from_id, to_id])

    try:
        async with db.begin():
            # ------------------------------------------------------------------
            # 1. Lock both rows atomically in sorted order.
            # ------------------------------------------------------------------
            result = await db.execute(
                text(
                    "SELECT user_id, balance, credit_limit "
                    "FROM users_taz_balance "
                    "WHERE user_id IN (:uid_a, :uid_b) "
                    "ORDER BY user_id "
                    "FOR UPDATE"
                ),
                {"uid_a": uid_a, "uid_b": uid_b},
            )
            rows = {str(r["user_id"]): r for r in result.mappings().all()}

            # ------------------------------------------------------------------
            # 2. Validate both users exist.
            # ------------------------------------------------------------------
            if from_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Sender {from_id} not found in Vault.",
                )
            if to_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Recipient {to_id} not found in Vault.",
                )

            sender    = rows[from_id]
            recipient = rows[to_id]  # noqa: F841 — validated above

            # ------------------------------------------------------------------
            # 3. Verify the sender has sufficient funds (balance + credit).
            # ------------------------------------------------------------------
            available = Decimal(str(sender["balance"])) + Decimal(str(sender["credit_limit"]))
            if available < payload.amount:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        f"Insufficient funds. Available: {available} Taz, "
                        f"Requested: {payload.amount} Taz."
                    ),
                )

            # ------------------------------------------------------------------
            # 4. Apply the transfer — debit sender, credit recipient.
            # ------------------------------------------------------------------
            await db.execute(
                text(
                    "UPDATE users_taz_balance "
                    "SET balance = balance - :amount "
                    "WHERE user_id = :user_id"
                ),
                {"amount": str(payload.amount), "user_id": from_id},
            )

            await db.execute(
                text(
                    "UPDATE users_taz_balance "
                    "SET balance = balance + :amount "
                    "WHERE user_id = :user_id"
                ),
                {"amount": str(payload.amount), "user_id": to_id},
            )

            # ------------------------------------------------------------------
            # 5. Record the completed transaction in the ledger.
            # ------------------------------------------------------------------
            txn_id = str(uuid.uuid4())

            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed')"
                ),
                {
                    "txn_id":    txn_id,
                    "from_user": from_id,
                    "to_user":   to_id,
                    "amount":    str(payload.amount),
                },
            )

            logger.info(
                "Transfer completed — txn=%s amount=%s",
                txn_id,
                payload.amount,
            )

    except HTTPException:
        # Re-raise HTTP exceptions (validation / not-found) without recording
        # a failed ledger entry — these are client errors, not system failures.
        raise

    except Exception as exc:
        # ------------------------------------------------------------------
        # System-level failure path:
        # Record a 'failed' ledger entry in a NEW session (the original
        # session/transaction has been rolled back by now).
        # ------------------------------------------------------------------
        logger.error("Transaction failed — system error: %s", exc)

        try:
            async with AsyncSessionFactory() as error_db:
                async with error_db.begin():
                    await error_db.execute(
                        text(
                            "INSERT INTO transaction_ledger "
                            "(transaction_id, from_user, to_user, amount, status) "
                            "VALUES (:txn_id, :from_user, :to_user, :amount, 'failed')"
                        ),
                        {
                            "txn_id":    str(uuid.uuid4()),
                            "from_user": from_id,
                            "to_user":   to_id,
                            "amount":    str(payload.amount),
                        },
                    )
        except Exception as ledger_exc:
            logger.error("Failed to record error in ledger: %s", ledger_exc)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transaction failed due to an internal error.",
        ) from exc

    return TransactionResponse(
        transaction_id=uuid.UUID(txn_id),
        status="completed",
        from_user=payload.from_user,
        to_user=payload.to_user,
        amount=payload.amount,
    )


# ---------------------------------------------------------------------------
# POST /transactions/transfer
# ---------------------------------------------------------------------------

@app.post("/transactions/transfer", response_model=TransferResponse, status_code=201)
@limiter.limit("20/minute")
async def transfer(
    request: Request,  # Required by slowapi
    payload: TransferRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> TransferResponse:
    """
    Atomically transfers Taz between any two wallets.

    This is the canonical transfer endpoint for all inter-wallet movements in
    the Tazo order / escrow flow:

      ESCROW_LOCK    : buyer_wallet    → escrow_wallet   (funds reserved)
      ESCROW_RELEASE : escrow_wallet   → merchant_wallet (delivery confirmed)
      REFUND         : escrow_wallet   → buyer_wallet    (cancellation)
      TRANSFER       : any             → any             (general purpose)

    HTTP status codes:
      201 — transfer completed
      402 — insufficient funds (buyer cannot cover the order amount)
      404 — sender or recipient wallet not found
      422 — validation error (same sender/recipient, amount ≤ 0, etc.)

    ACID & safety properties — identical to POST /transaction:
      Atomicity   : debit + credit + ledger INSERT are one DB transaction.
      Consistency : available = balance + credit_limit checked before writes.
      Isolation   : SELECT … FOR UPDATE with deadlock-safe UUID sort order.
      Durability  : PostgreSQL WAL guarantees durability on commit.
    """
    from_id = str(payload.from_user)
    to_id   = str(payload.to_user)

    if from_id == to_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="from_user and to_user must be different.",
        )

    # Sanitise transaction_type to prevent injection into the ledger.
    allowed_types = {"TRANSFER", "ESCROW_LOCK", "ESCROW_RELEASE", "REFUND", "MINTING", "TOPUP", "BONUS"}
    txn_type = payload.transaction_type.upper()
    if txn_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"transaction_type must be one of: {', '.join(sorted(allowed_types))}.",
        )

    # Consistent lock order — lexicographic sort prevents deadlocks.
    uid_a, uid_b = sorted([from_id, to_id])

    txn_id: str = ""

    try:
        async with db.begin():
            # ------------------------------------------------------------------
            # 1. Lock both rows in consistent order.
            # ------------------------------------------------------------------
            result = await db.execute(
                text(
                    "SELECT user_id, balance, credit_limit "
                    "FROM users_taz_balance "
                    "WHERE user_id IN (:uid_a, :uid_b) "
                    "ORDER BY user_id "
                    "FOR UPDATE"
                ),
                {"uid_a": uid_a, "uid_b": uid_b},
            )
            rows = {str(r["user_id"]): r for r in result.mappings().all()}

            # ------------------------------------------------------------------
            # 2. Validate both wallets exist.
            # ------------------------------------------------------------------
            if from_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Sender wallet {from_id} not found in Vault.",
                )
            if to_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Recipient wallet {to_id} not found in Vault.",
                )

            sender = rows[from_id]

            # ------------------------------------------------------------------
            # 3. Check available funds. Return 402 (Payment Required) — the
            #    semantically correct code for "the buyer cannot pay".
            # ------------------------------------------------------------------
            available = Decimal(str(sender["balance"])) + Decimal(str(sender["credit_limit"]))
            if available < payload.amount:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=(
                        f"Insufficient funds. Available: {available} Taz, "
                        f"Requested: {payload.amount} Taz."
                    ),
                )

            # ------------------------------------------------------------------
            # 4. Apply the transfer atomically.
            # ------------------------------------------------------------------
            await db.execute(
                text(
                    "UPDATE users_taz_balance "
                    "SET balance = balance - :amount "
                    "WHERE user_id = :user_id"
                ),
                {"amount": str(payload.amount), "user_id": from_id},
            )
            await db.execute(
                text(
                    "UPDATE users_taz_balance "
                    "SET balance = balance + :amount "
                    "WHERE user_id = :user_id"
                ),
                {"amount": str(payload.amount), "user_id": to_id},
            )

            # ------------------------------------------------------------------
            # 5. Write ledger entry with type tag and optional order reference.
            # ------------------------------------------------------------------
            txn_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', :txn_type)"
                ),
                {
                    "txn_id":    txn_id,
                    "from_user": from_id,
                    "to_user":   to_id,
                    "amount":    str(payload.amount),
                    "txn_type":  txn_type,
                },
            )

            logger.info(
                "Transfer completed — txn=%s type=%s amount=%s order=%s",
                txn_id, txn_type, payload.amount, payload.order_id,
            )

    except HTTPException:
        raise

    except Exception as exc:
        logger.error("Transfer failed — system error: %s", exc)

        try:
            async with AsyncSessionFactory() as error_db:
                async with error_db.begin():
                    await error_db.execute(
                        text(
                            "INSERT INTO transaction_ledger "
                            "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                            "VALUES (:txn_id, :from_user, :to_user, :amount, 'failed', :txn_type)"
                        ),
                        {
                            "txn_id":    str(uuid.uuid4()),
                            "from_user": from_id,
                            "to_user":   to_id,
                            "amount":    str(payload.amount),
                            "txn_type":  txn_type,
                        },
                    )
        except Exception as ledger_exc:
            logger.error("Failed to record error in ledger: %s", ledger_exc)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transfer failed due to an internal error.",
        ) from exc

    return TransferResponse(
        transaction_id=uuid.UUID(txn_id),
        status="completed",
        from_user=payload.from_user,
        to_user=payload.to_user,
        amount=payload.amount,
        order_id=payload.order_id,
        transaction_type=txn_type,
    )


# ---------------------------------------------------------------------------
# POST /wallets/create
# ---------------------------------------------------------------------------

@app.post("/wallets/create", response_model=WalletCreateResponse, status_code=201)
@limiter.limit("20/minute")
async def create_wallet(
    request: Request,  # Required by slowapi
    payload: WalletCreateRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> WalletCreateResponse:
    """
    Creates a new Taz wallet for a user.

    Called by Tazo-Go / Tazo-Web immediately after a user is registered
    in the central User service.  The user_id must be the canonical UUID
    issued by that service.

    Returns 409 Conflict if a wallet for the given user_id already exists.
    Rate limit: 20 requests/minute per calling IP.
    """
    user_id_str = str(payload.user_id)

    try:
        async with db.begin():
            result = await db.execute(
                text(
                    "INSERT INTO users_taz_balance (user_id, balance, credit_limit) "
                    "VALUES (:user_id, 0, :credit_limit) "
                    "RETURNING user_id, balance, credit_limit, updated_at AS created_at"
                ),
                {
                    "user_id":      user_id_str,
                    "credit_limit": str(payload.credit_limit),
                },
            )
            row = result.mappings().first()

    except Exception as exc:
        # asyncpg raises UniqueViolationError (wrapped by SQLAlchemy) on PK conflict.
        exc_str = str(exc).lower()
        if "unique" in exc_str or "duplicate" in exc_str:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Wallet for user {payload.user_id} already exists.",
            )
        logger.error("Wallet creation failed for user %s: %s", user_id_str, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Wallet creation failed due to an internal error.",
        ) from exc

    logger.info("Wallet created — user=%s credit_limit=%s", user_id_str, payload.credit_limit)

    # ── Welcome bonus: best-effort credit from Treasury ───────────────────────
    if payload.welcome_bonus and TREASURY_WALLET_ID:
        try:
            treasury_id  = TREASURY_WALLET_ID
            bonus_amount = WELCOME_BONUS_TAZ
            uid_a, uid_b = sorted([treasury_id, user_id_str])
            async with AsyncSessionFactory() as bonus_db:
                async with bonus_db.begin():
                    tbal = await bonus_db.execute(
                        text("SELECT balance FROM users_taz_balance WHERE user_id = :uid FOR UPDATE"),
                        {"uid": treasury_id},
                    )
                    trow = tbal.mappings().first()
                    if trow and Decimal(str(trow["balance"])) >= bonus_amount:
                        await bonus_db.execute(
                            text("UPDATE users_taz_balance SET balance = balance - :amt WHERE user_id = :uid"),
                            {"amt": str(bonus_amount), "uid": treasury_id},
                        )
                        await bonus_db.execute(
                            text("UPDATE users_taz_balance SET balance = balance + :amt WHERE user_id = :uid"),
                            {"amt": str(bonus_amount), "uid": user_id_str},
                        )
                        await bonus_db.execute(
                            text(
                                "INSERT INTO transaction_ledger "
                                "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                                "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'BONUS')"
                            ),
                            {
                                "txn_id":    str(uuid.uuid4()),
                                "from_user": treasury_id,
                                "to_user":   user_id_str,
                                "amount":    str(bonus_amount),
                            },
                        )
                        logger.info(
                            "Welcome bonus %s Taz credited to new wallet %s", bonus_amount, user_id_str
                        )
                    else:
                        logger.warning("Treasury low — welcome bonus skipped for %s", user_id_str)
        except Exception as bonus_exc:
            logger.error("Welcome bonus failed for %s: %s", user_id_str, bonus_exc)

    return WalletCreateResponse(**row)


# ---------------------------------------------------------------------------
# POST /admin/mint
# ---------------------------------------------------------------------------

@app.post("/admin/mint", response_model=MintResponse, status_code=201)
@limiter.limit("10/minute")
async def mint_taz(
    request: Request,  # Required by slowapi
    payload: MintRequest,
    _auth: AdminAuth,
    db: DBSession,
) -> MintResponse:
    """
    Mints new Taz into the Treasury wallet.

    ONLY the TREASURY_WALLET_ID configured in the server environment may
    receive minted Taz.  Any attempt to mint into a different wallet is
    rejected with 403 — even with a valid admin key.

    The operation is fully ACID:
      1. Treasury balance is increased inside a single transaction.
      2. A MINTING ledger entry (from_user=NULL) is written in the same
         transaction — both succeed or both roll back atomically.

    Rate limit: 10 requests/minute per calling IP (stricter than regular).
    """
    treasury_str = TREASURY_WALLET_ID

    async with db.begin():
        # ------------------------------------------------------------------
        # 1. Lock the Treasury row and verify it exists.
        # ------------------------------------------------------------------
        result = await db.execute(
            text(
                "SELECT user_id, balance "
                "FROM users_taz_balance "
                "WHERE user_id = :user_id "
                "FOR UPDATE"
            ),
            {"user_id": treasury_str},
        )
        row = result.mappings().first()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "Treasury wallet not found. "
                    "Create it first via POST /wallets/create."
                ),
            )

        # ------------------------------------------------------------------
        # 2. Apply the mint — credit the Treasury.
        # ------------------------------------------------------------------
        update_result = await db.execute(
            text(
                "UPDATE users_taz_balance "
                "SET balance = balance + :amount "
                "WHERE user_id = :user_id "
                "RETURNING balance"
            ),
            {"amount": str(payload.amount), "user_id": treasury_str},
        )
        new_balance = update_result.scalar_one()

        # ------------------------------------------------------------------
        # 3. Write MINTING ledger entry (from_user is NULL by design).
        # ------------------------------------------------------------------
        txn_id = str(uuid.uuid4())
        await db.execute(
            text(
                "INSERT INTO transaction_ledger "
                "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                "VALUES (:txn_id, NULL, :to_user, :amount, 'completed', 'MINTING')"
            ),
            {
                "txn_id":  txn_id,
                "to_user": treasury_str,
                "amount":  str(payload.amount),
            },
        )

    logger.info(
        "MINTING completed — txn=%s amount=%s treasury=%s note=%r",
        txn_id,
        payload.amount,
        treasury_str,
        payload.note,
    )

    return MintResponse(
        transaction_id=uuid.UUID(txn_id),
        treasury_id=uuid.UUID(treasury_str),
        amount=payload.amount,
        new_balance=Decimal(str(new_balance)),
        status="completed",
    )


# ---------------------------------------------------------------------------
# GET /transactions/{user_id}
# ---------------------------------------------------------------------------

@app.get("/transactions/{user_id}", response_model=TransactionHistoryResponse)
@limiter.limit("30/minute")
async def get_transaction_history(
    request: Request,  # Required by slowapi
    user_id: UUID,
    _auth: VaultAuth,
    db: DBSession,
    limit:  int = 50,
    offset: int = 0,
) -> TransactionHistoryResponse:
    """
    Returns paginated transaction history for a user (sent and received).

    Query parameters:
      limit  — number of records to return (1–100, default 50)
      offset — number of records to skip for pagination (default 0)

    Results are ordered by created_at DESC (most recent first).
    The response includes a `total` count for the caller to implement
    client-side pagination controls.

    Rate limit: 30 requests/minute per calling IP.
    """
    if not (1 <= limit <= 100):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="limit must be between 1 and 100.",
        )
    if offset < 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="offset must be >= 0.",
        )

    user_id_str = str(user_id)

    # Verify the user exists in the Vault.
    exists_result = await db.execute(
        text("SELECT 1 FROM users_taz_balance WHERE user_id = :user_id"),
        {"user_id": user_id_str},
    )
    if exists_result.first() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found in Vault.",
        )

    # Total count (for pagination metadata).
    count_result = await db.execute(
        text(
            "SELECT COUNT(*) FROM transaction_ledger "
            "WHERE from_user = :uid OR to_user = :uid"
        ),
        {"uid": user_id_str},
    )
    total: int = count_result.scalar_one()

    # Paginated rows.
    rows_result = await db.execute(
        text(
            "SELECT transaction_id, from_user, to_user, amount, "
            "       status, transaction_type, created_at "
            "FROM transaction_ledger "
            "WHERE from_user = :uid OR to_user = :uid "
            "ORDER BY created_at DESC "
            "LIMIT :limit OFFSET :offset"
        ),
        {"uid": user_id_str, "limit": limit, "offset": offset},
    )
    rows = rows_result.mappings().all()

    return TransactionHistoryResponse(
        user_id=user_id,
        total=total,
        limit=limit,
        offset=offset,
        transactions=[TransactionRecord(**r) for r in rows],
    )


# ---------------------------------------------------------------------------
# POST /escrow/lock
# ---------------------------------------------------------------------------

@app.post("/escrow/lock", response_model=EscrowLockResponse, status_code=201)
@limiter.limit("30/minute")
async def escrow_lock(
    request: Request,
    payload: EscrowLockRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> EscrowLockResponse:
    """
    Lock buyer funds into the platform ESCROW_WALLET.

    Flow:
      1. Validate ESCROW_WALLET_ID is configured.
      2. Debit buyer_wallet, credit ESCROW_WALLET in a single ACID transaction.
      3. Write ESCROW_LOCK ledger entry tagged with order_id.
      4. Fire payment.locked webhook to Tazo-Go (fire-and-forget).
      5. SMS admin if amount >= SMS_THRESHOLD_NIS.

    Returns 402 if buyer has insufficient funds.
    Returns 503 if ESCROW_WALLET_ID is not configured.
    """
    if not ESCROW_WALLET_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Escrow wallet not configured on Vault. Set ESCROW_WALLET_ID.",
        )

    buyer_id  = str(payload.buyer_wallet_id)
    escrow_id = ESCROW_WALLET_ID

    if buyer_id == escrow_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="buyer_wallet_id must differ from the escrow wallet.",
        )

    # Consistent lock order (deadlock prevention).
    uid_a, uid_b = sorted([buyer_id, escrow_id])
    txn_id: str = ""

    try:
        async with db.begin():
            # ------------------------------------------------------------------
            # 1. Lock both rows.
            # ------------------------------------------------------------------
            result = await db.execute(
                text(
                    "SELECT user_id, balance, credit_limit "
                    "FROM users_taz_balance "
                    "WHERE user_id IN (:uid_a, :uid_b) "
                    "ORDER BY user_id "
                    "FOR UPDATE"
                ),
                {"uid_a": uid_a, "uid_b": uid_b},
            )
            rows = {str(r["user_id"]): r for r in result.mappings().all()}

            # ------------------------------------------------------------------
            # 2. Validate both wallets exist.
            # ------------------------------------------------------------------
            if buyer_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Buyer wallet {payload.buyer_wallet_id} not found in Vault.",
                )
            if escrow_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Escrow wallet not found in Vault. Run /wallets/create for ESCROW_WALLET_ID.",
                )

            buyer = rows[buyer_id]

            # ------------------------------------------------------------------
            # 3. Sufficient funds check.
            # ------------------------------------------------------------------
            available = (
                Decimal(str(buyer["balance"]))
                + Decimal(str(buyer["credit_limit"]))
            )
            if available < payload.amount:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=(
                        f"Insufficient funds. Available: {available} Taz, "
                        f"Required: {payload.amount} Taz."
                    ),
                )

            # ------------------------------------------------------------------
            # 4. Apply debit / credit atomically.
            # ------------------------------------------------------------------
            await db.execute(
                text(
                    "UPDATE users_taz_balance SET balance = balance - :amount "
                    "WHERE user_id = :uid"
                ),
                {"amount": str(payload.amount), "uid": buyer_id},
            )
            await db.execute(
                text(
                    "UPDATE users_taz_balance SET balance = balance + :amount "
                    "WHERE user_id = :uid"
                ),
                {"amount": str(payload.amount), "uid": escrow_id},
            )

            # ------------------------------------------------------------------
            # 5. Write ESCROW_LOCK ledger entry.
            # ------------------------------------------------------------------
            txn_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'ESCROW_LOCK')"
                ),
                {
                    "txn_id":    txn_id,
                    "from_user": buyer_id,
                    "to_user":   escrow_id,
                    "amount":    str(payload.amount),
                },
            )

        logger.info(
            "ESCROW_LOCK — txn=%s buyer=%s amount=%s order=%s",
            txn_id, buyer_id, payload.amount, payload.order_id,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("ESCROW_LOCK failed — order=%s: %s", payload.order_id, exc)
        # Record failed attempt in ledger.
        try:
            async with AsyncSessionFactory() as err_db:
                async with err_db.begin():
                    await err_db.execute(
                        text(
                            "INSERT INTO transaction_ledger "
                            "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                            "VALUES (:txn_id, :from_user, :to_user, :amount, 'failed', 'ESCROW_LOCK')"
                        ),
                        {
                            "txn_id":    str(uuid.uuid4()),
                            "from_user": buyer_id,
                            "to_user":   escrow_id,
                            "amount":    str(payload.amount),
                        },
                    )
        except Exception as ledger_exc:
            logger.error("Failed to record ESCROW_LOCK failure in ledger: %s", ledger_exc)
        # Notify admin of payment failure.
        asyncio.create_task(_sms_admin(
            f"🚨 TAZO Vault\nESCROW_LOCK FAILED\n"
            f"Order: {payload.order_id}\nAmount: {payload.amount} Taz\n"
            f"Error: {str(exc)[:120]}"
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Escrow lock failed due to an internal error.",
        ) from exc

    # ── Post-commit side-effects (fire-and-forget) ────────────────────────
    # Notify Tazo-Go so it can auto-dispatch.
    asyncio.create_task(_fire_payment_locked_webhook(
        order_id=payload.order_id,
        vault_tx_id=txn_id,
        amount=payload.amount,
        buyer_wallet_id=buyer_id,
    ))
    # SMS admin for high-value transactions.
    if payload.amount >= SMS_THRESHOLD_NIS:
        asyncio.create_task(_sms_admin(
            f"💳 TAZO Vault\nESCROW_LOCK ✅\n"
            f"Order: {payload.order_id}\n"
            f"Amount: {payload.amount} Taz\n"
            f"Buyer wallet: ...{buyer_id[-8:]}"
        ))

    return EscrowLockResponse(
        transaction_id=uuid.UUID(txn_id),
        order_id=payload.order_id,
        amount=payload.amount,
        escrow_wallet=uuid.UUID(escrow_id),
        status="locked",
    )


# ---------------------------------------------------------------------------
# POST /escrow/release
# ---------------------------------------------------------------------------

@app.post("/escrow/release", response_model=EscrowReleaseResponse, status_code=201)
@limiter.limit("30/minute")
async def escrow_release(
    request: Request,
    payload: EscrowReleaseRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> EscrowReleaseResponse:
    """
    Release escrowed funds to the driver after delivery confirmation.

    Flow:
      1. Split `amount` into driver_amount and fee_amount based on TAZO_FEE_PCT.
      2. ESCROW_WALLET → driver_wallet  (driver_amount)  — ESCROW_RELEASE entry.
      3. ESCROW_WALLET → TREASURY_WALLET (fee_amount)    — TRANSFER entry.
      Both transfers are committed in a single ACID transaction.
      4. SMS admin for every release (amount or fee context).

    The 2-minute cool-down for customer disputes is enforced by Tazo-Go before
    calling this endpoint — Vault does not re-enforce it.

    Returns 404 if escrow or driver wallet not found.
    Returns 503 if ESCROW_WALLET_ID is not configured.
    """
    if not ESCROW_WALLET_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Escrow wallet not configured on Vault. Set ESCROW_WALLET_ID.",
        )

    escrow_id   = ESCROW_WALLET_ID
    driver_id   = str(payload.driver_wallet_id)
    treasury_id = TREASURY_WALLET_ID

    # Fee split (quantised to 2 decimal places to avoid sub-cent rounding drift).
    fee_amount    = (payload.amount * TAZO_FEE_PCT / 100).quantize(_CENT, rounding=ROUND_HALF_UP)
    driver_amount = (payload.amount - fee_amount).quantize(_CENT, rounding=ROUND_HALF_UP)

    if driver_amount <= Decimal("0"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="After fee deduction the driver_amount is zero or negative.",
        )

    # Lock all three rows in consistent UUID order (deadlock prevention).
    uids_sorted = sorted([escrow_id, driver_id, treasury_id])

    release_txn_id: str = ""
    fee_txn_id:     str = ""

    try:
        async with db.begin():
            # ------------------------------------------------------------------
            # 1. Lock all three wallets.
            # ------------------------------------------------------------------
            result = await db.execute(
                text(
                    "SELECT user_id, balance "
                    "FROM users_taz_balance "
                    "WHERE user_id IN (:u0, :u1, :u2) "
                    "ORDER BY user_id "
                    "FOR UPDATE"
                ),
                {"u0": uids_sorted[0], "u1": uids_sorted[1], "u2": uids_sorted[2]},
            )
            rows = {str(r["user_id"]): r for r in result.mappings().all()}

            # ------------------------------------------------------------------
            # 2. Validate all three wallets exist.
            # ------------------------------------------------------------------
            for wallet_id, label in [
                (escrow_id,   "Escrow"),
                (driver_id,   "Driver"),
                (treasury_id, "Treasury"),
            ]:
                if wallet_id not in rows:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"{label} wallet {wallet_id} not found in Vault.",
                    )

            # ------------------------------------------------------------------
            # 3. Check escrow has enough balance.
            # ------------------------------------------------------------------
            escrow_balance = Decimal(str(rows[escrow_id]["balance"]))
            if escrow_balance < payload.amount:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Escrow balance ({escrow_balance} Taz) is less than "
                        f"release amount ({payload.amount} Taz) for order {payload.order_id}. "
                        "Possible duplicate release."
                    ),
                )

            # ------------------------------------------------------------------
            # 4a. Transfer driver_amount: ESCROW → DRIVER (ESCROW_RELEASE).
            # ------------------------------------------------------------------
            await db.execute(
                text(
                    "UPDATE users_taz_balance SET balance = balance - :amount "
                    "WHERE user_id = :uid"
                ),
                {"amount": str(driver_amount + fee_amount), "uid": escrow_id},
            )
            await db.execute(
                text(
                    "UPDATE users_taz_balance SET balance = balance + :amount "
                    "WHERE user_id = :uid"
                ),
                {"amount": str(driver_amount), "uid": driver_id},
            )

            # ------------------------------------------------------------------
            # 4b. Transfer fee_amount: direct credit TREASURY (no double-debit).
            # ------------------------------------------------------------------
            await db.execute(
                text(
                    "UPDATE users_taz_balance SET balance = balance + :amount "
                    "WHERE user_id = :uid"
                ),
                {"amount": str(fee_amount), "uid": treasury_id},
            )

            # ------------------------------------------------------------------
            # 5. Write two ledger entries.
            # ------------------------------------------------------------------
            release_txn_id = str(uuid.uuid4())
            fee_txn_id     = str(uuid.uuid4())

            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'ESCROW_RELEASE')"
                ),
                {
                    "txn_id":    release_txn_id,
                    "from_user": escrow_id,
                    "to_user":   driver_id,
                    "amount":    str(driver_amount),
                },
            )
            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'TRANSFER')"
                ),
                {
                    "txn_id":    fee_txn_id,
                    "from_user": escrow_id,
                    "to_user":   treasury_id,
                    "amount":    str(fee_amount),
                },
            )

        logger.info(
            "ESCROW_RELEASE — release_txn=%s fee_txn=%s driver=%s driver_amount=%s fee=%s order=%s",
            release_txn_id, fee_txn_id, driver_id, driver_amount, fee_amount, payload.order_id,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("ESCROW_RELEASE failed — order=%s: %s", payload.order_id, exc)
        asyncio.create_task(_sms_admin(
            f"🚨 TAZO Vault\nESCROW_RELEASE FAILED\n"
            f"Order: {payload.order_id}\nAmount: {payload.amount} Taz\n"
            f"Driver: ...{driver_id[-8:]}\nError: {str(exc)[:120]}"
        ))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Escrow release failed due to an internal error.",
        ) from exc

    # ── Post-commit SMS notification ─────────────────────────────────────
    asyncio.create_task(_sms_admin(
        f"✅ TAZO Vault\nESCROW_RELEASE\n"
        f"Order: {payload.order_id}\n"
        f"Driver: ...{driver_id[-8:]}\n"
        f"Payout: {driver_amount} Taz  |  Fee: {fee_amount} Taz ({TAZO_FEE_PCT}%)"
    ))

    return EscrowReleaseResponse(
        release_tx_id=uuid.UUID(release_txn_id),
        fee_tx_id=uuid.UUID(fee_txn_id),
        order_id=payload.order_id,
        driver_amount=driver_amount,
        fee_amount=fee_amount,
        driver_wallet=uuid.UUID(driver_id),
        treasury_wallet=uuid.UUID(treasury_id),
        status="released",
    )


# ---------------------------------------------------------------------------
# POST /wallets/topup
# ---------------------------------------------------------------------------

@app.post("/wallets/topup", response_model=TopupResponse, status_code=201)
@limiter.limit("30/minute")
async def topup_wallet(
    request: Request,
    payload: TopupRequest,
    _auth: VaultAuth,
    db: DBSession,
) -> TopupResponse:
    """
    Top-up a user wallet from the Treasury (GreenInvoice payment confirmed).

    Mechanics:
      - base_amount    = payload.amount            (1 ILS → 1 Taz)
      - bonus_amount   = round(base * 10%, 2)      (10% gift)
      - total_credited = base_amount + bonus_amount

    Both amounts transfer from Treasury → user wallet in a single ACID transaction.
    Two ledger entries: TOPUP (base) and BONUS (10% gift).

    Returns 404 if target wallet does not exist.
    Returns 503 if Treasury is not configured or has insufficient balance.
    Rate limit: 30 requests/minute per calling IP.
    """
    if not TREASURY_WALLET_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Treasury wallet not configured on Vault.",
        )

    user_id_str  = str(payload.wallet_id)
    treasury_id  = TREASURY_WALLET_ID
    base_amount  = payload.amount.quantize(_CENT, rounding=ROUND_HALF_UP)
    bonus_amount = (base_amount * Decimal("0.10")).quantize(_CENT, rounding=ROUND_HALF_UP)
    total        = base_amount + bonus_amount
    uid_a, uid_b = sorted([treasury_id, user_id_str])

    topup_txn_id: str = ""
    bonus_txn_id: str = ""

    try:
        async with db.begin():
            # 1. Lock both rows in sorted order (deadlock prevention).
            result = await db.execute(
                text(
                    "SELECT user_id, balance "
                    "FROM users_taz_balance "
                    "WHERE user_id IN (:uid_a, :uid_b) "
                    "ORDER BY user_id FOR UPDATE"
                ),
                {"uid_a": uid_a, "uid_b": uid_b},
            )
            rows = {str(r["user_id"]): r for r in result.mappings().all()}

            # 2. Validate.
            if user_id_str not in rows:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Wallet {payload.wallet_id} not found in Vault.",
                )
            if treasury_id not in rows:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Treasury wallet not found in Vault.",
                )

            treasury_balance = Decimal(str(rows[treasury_id]["balance"]))
            if treasury_balance < total:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        f"Treasury insufficient: {treasury_balance} Taz available, "
                        f"{total} Taz needed."
                    ),
                )

            # 3. Debit Treasury, credit user.
            await db.execute(
                text("UPDATE users_taz_balance SET balance = balance - :amt WHERE user_id = :uid"),
                {"amt": str(total), "uid": treasury_id},
            )
            await db.execute(
                text("UPDATE users_taz_balance SET balance = balance + :amt WHERE user_id = :uid"),
                {"amt": str(total), "uid": user_id_str},
            )

            # 4a. TOPUP ledger entry (base amount).
            topup_txn_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'TOPUP')"
                ),
                {
                    "txn_id":    topup_txn_id,
                    "from_user": treasury_id,
                    "to_user":   user_id_str,
                    "amount":    str(base_amount),
                },
            )

            # 4b. BONUS ledger entry (10% gift).
            bonus_txn_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO transaction_ledger "
                    "(transaction_id, from_user, to_user, amount, status, transaction_type) "
                    "VALUES (:txn_id, :from_user, :to_user, :amount, 'completed', 'BONUS')"
                ),
                {
                    "txn_id":    bonus_txn_id,
                    "from_user": treasury_id,
                    "to_user":   user_id_str,
                    "amount":    str(bonus_amount),
                },
            )

        logger.info(
            "TOPUP — topup_txn=%s bonus_txn=%s wallet=%s base=%s bonus=%s total=%s ref=%r",
            topup_txn_id, bonus_txn_id, user_id_str,
            base_amount, bonus_amount, total, payload.reference,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("TOPUP failed — wallet=%s: %s", user_id_str, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Top-up failed due to an internal error.",
        ) from exc

    return TopupResponse(
        topup_tx_id=uuid.UUID(topup_txn_id),
        bonus_tx_id=uuid.UUID(bonus_txn_id),
        wallet_id=payload.wallet_id,
        base_amount=base_amount,
        bonus_amount=bonus_amount,
        total_credited=total,
        reference=payload.reference,
    )
