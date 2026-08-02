from unittest.mock import Mock

from lsa.seed import BOOTSTRAP_LOCK_ID, acquire_bootstrap_lock


def test_bootstrap_uses_transaction_lock_on_postgresql():
    db = Mock()
    db.get_bind.return_value.dialect.name = "postgresql"

    acquire_bootstrap_lock(db)

    statement, parameters = db.execute.call_args.args
    assert str(statement) == "SELECT pg_advisory_xact_lock(:lock_id)"
    assert parameters == {"lock_id": BOOTSTRAP_LOCK_ID}


def test_bootstrap_does_not_use_advisory_lock_on_sqlite():
    db = Mock()
    db.get_bind.return_value.dialect.name = "sqlite"

    acquire_bootstrap_lock(db)

    db.execute.assert_not_called()
