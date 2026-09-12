import pytest
@pytest.fixture(autouse=True)
def synthetic_core(monkeypatch):
    # Test-only trusted module, never enabled by the application.
    monkeypatch.setenv("CVEVIDENCE_CORE_MODULE","tests.fixtures.core_stub")
