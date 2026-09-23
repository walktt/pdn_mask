import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


if sys.platform == "win32":
    # psycopg в async-режиме не работает поверх ProactorEventLoop (дефолт pytest-asyncio на Windows)
    @pytest.fixture(scope="session")
    def event_loop_policy():
        return asyncio.WindowsSelectorEventLoopPolicy()
