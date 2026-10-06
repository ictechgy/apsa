from pathlib import Path

import pytest

from mobile_audit.cli import demo_target
from mobile_audit.store import Store


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "state")
    yield value
    value.close()


@pytest.fixture
def demo(tmp_path):
    return demo_target(tmp_path / "demo")


@pytest.fixture
def apk():
    return Path(__file__).parent / "fixtures/Test-debug.apk"
