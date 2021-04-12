# vim: ts=4:sw=4:et:cc=120

import pytest

from ace.system.database import DatabaseACESystem
from ace.system.threaded import ThreadedACESystem


class TestSystem(DatabaseACESystem, ThreadedACESystem):
    pass


@pytest.fixture
async def system(tmpdir):
    system = TestSystem(db_url="sqlite+aiosqlite://", storage_root=str(tmpdir))
    await system.initialize()
    await system.create_database()
    await system.start()

    yield system

    await system.stop()


@pytest.fixture
async def root(system):
    root = system.new_root()
    yield root
    await root.discard()
