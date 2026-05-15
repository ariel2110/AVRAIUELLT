"""
Tests for vault.com TAZ Currency Vault API.
Run inside vault_bridge container:
  python3 -m pytest /app/tests/test_vault.py -v
"""
import uuid
import pytest
from httpx import AsyncClient, ASGITransport

INTERNAL_KEY = 'f1443b9f620553a01ae6a88ee2846d14b92b79d8451fc13d79ac1c3899bff6c5'
ADMIN_KEY    = 'c9e9163c0b6bdd8db6ab0dbdd926d9aebe06d717eed05df08d718321d99a3186'
TREASURY_ID  = '912a0289-6bcb-4631-9ff6-10993720bad8'

IH = {'X-Vault-Internal-Key': INTERNAL_KEY}
AH = {'X-Vault-Admin-Key':    ADMIN_KEY}


@pytest.fixture(scope='session')
def app():
    import sys; sys.path.insert(0, '/app')
    from main import app as vault_app
    return vault_app


class TestHealth:
    async def test_health_ok(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.get('/health')
        assert r.status_code == 200
        assert r.json()['status'] == 'ok'

    async def test_health_no_auth_needed(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.get('/health')
        assert r.status_code == 200


class TestAuth:
    async def test_no_key_returns_403(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/wallets/create', json={'user_id': str(uuid.uuid4())})
        assert r.status_code == 403

    async def test_wrong_key_returns_403(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/wallets/create',
                             json={'user_id': str(uuid.uuid4())},
                             headers={'X-Vault-Internal-Key': 'wrong-key'})
        assert r.status_code == 403

    async def test_admin_key_not_accepted_on_regular_endpoint(self, app):
        """Admin key in X-Vault-Internal-Key header -> 403 (wrong key set)."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/wallets/create',
                             json={'user_id': str(uuid.uuid4())},
                             headers={'X-Vault-Internal-Key': ADMIN_KEY})
        assert r.status_code == 403

    async def test_internal_key_not_accepted_on_admin_endpoint(self, app):
        """Internal key in X-Vault-Admin-Key header -> 403 (wrong key set)."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/admin/mint',
                             json={'amount': '10', 'note': 'test'},
                             headers={'X-Vault-Admin-Key': INTERNAL_KEY})
        assert r.status_code == 403

    async def test_no_admin_key_returns_403(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/admin/mint', json={'amount': '10', 'note': 'test'})
        assert r.status_code == 403


class TestWallet:
    async def test_create_wallet(self, app):
        user_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/wallets/create', json={'user_id': user_id}, headers=IH)
        assert r.status_code in (200, 201)
        data = r.json()
        assert 'user_id' in data
        assert str(data['user_id']) == user_id

    async def test_create_wallet_idempotent(self, app):
        user_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r1 = await c.post('/wallets/create', json={'user_id': user_id}, headers=IH)
            r2 = await c.post('/wallets/create', json={'user_id': user_id}, headers=IH)
        assert r1.status_code in (200, 201)
        # Second creation of same user_id returns 409 Conflict
        assert r2.status_code in (200, 201, 409)
        if r2.status_code in (200, 201):
            assert str(r1.json()['user_id']) == str(r2.json()['user_id'])

    async def test_balance_new_wallet(self, app):
        user_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            await c.post('/wallets/create', json={'user_id': user_id}, headers=IH)
            r = await c.get(f'/balance/{user_id}', headers=IH)
        assert r.status_code == 200
        # welcome_bonus=True credits 30 TAZ by default
        assert float(r.json()['balance']) >= 0

    async def test_balance_nonexistent_user_404(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.get(f'/balance/{str(uuid.uuid4())}', headers=IH)
        assert r.status_code == 404


class TestAdminMint:
    async def test_mint_to_treasury(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/admin/mint',
                             json={'amount': '100', 'note': 'test mint'},
                             headers=AH)
        assert r.status_code in (200, 201)
        data = r.json()
        assert 'transaction_id' in data
        assert str(data['treasury_id']) == TREASURY_ID
        assert float(data['amount']) == 100.0
        assert data['status'] == 'completed'

    async def test_mint_negative_amount_rejected(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/admin/mint',
                             json={'amount': '-100', 'note': 'negative'},
                             headers=AH)
        assert r.status_code in (400, 422)

    async def test_mint_zero_amount_rejected(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/admin/mint',
                             json={'amount': '0', 'note': 'zero'},
                             headers=AH)
        assert r.status_code in (400, 422)


class TestTransfer:
    async def test_transfer_between_wallets(self, app):
        sender_id   = str(uuid.uuid4())
        receiver_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            await c.post('/wallets/create', json={'user_id': sender_id}, headers=IH)
            await c.post('/wallets/create', json={'user_id': receiver_id}, headers=IH)
            # Mint to treasury, then fund sender
            await c.post('/admin/mint', json={'amount': '200', 'note': 'fund'}, headers=AH)
            await c.post('/transactions/transfer',
                         json={'from_user': TREASURY_ID, 'to_user': sender_id, 'amount': '50'},
                         headers=IH)
            r = await c.post('/transactions/transfer',
                             json={'from_user': sender_id, 'to_user': receiver_id, 'amount': '20'},
                             headers=IH)
        assert r.status_code in (200, 201)
        data = r.json()
        assert 'transaction_id' in data
        assert data['status'] == 'completed'

    async def test_transfer_insufficient_funds(self, app):
        empty_user  = str(uuid.uuid4())
        target_user = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            await c.post('/wallets/create',
                         json={'user_id': empty_user, 'welcome_bonus': False}, headers=IH)
            await c.post('/wallets/create', json={'user_id': target_user}, headers=IH)
            r = await c.post('/transactions/transfer',
                             json={'from_user': empty_user, 'to_user': target_user, 'amount': '100'},
                             headers=IH)
        assert r.status_code in (400, 402, 422)

    async def test_transfer_nonexistent_user(self, app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            r = await c.post('/transactions/transfer',
                             json={'from_user': str(uuid.uuid4()),
                                   'to_user': str(uuid.uuid4()),
                                   'amount': '10'},
                             headers=IH)
        assert r.status_code == 404

    async def test_transaction_history(self, app):
        user_id = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as c:
            await c.post('/wallets/create', json={'user_id': user_id}, headers=IH)
            r = await c.get(f'/transactions/{user_id}', headers=IH)
        assert r.status_code == 200
        data = r.json()
        assert 'transactions' in data
        assert 'total' in data
