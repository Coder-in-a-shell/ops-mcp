import pytest

from ops_mcp.auth import ALL_SCOPES, Principal, TokenStore
from ops_mcp.data import Dataset
from ops_mcp.guard import Guard, RateLimit
from ops_mcp.service import OpsService


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture(scope="session")
def dataset():
    return Dataset.build()


@pytest.fixture
def guard(clock):
    return Guard(rate_limit=RateLimit(capacity=5, refill_per_sec=1.0), clock=clock, wall_clock=clock)


@pytest.fixture
def svc(dataset, guard):
    return OpsService(dataset, guard)


@pytest.fixture
def admin():
    return Principal("admin", frozenset(ALL_SCOPES), "admin01")


def make_principal(*scopes, name="agent"):
    return Principal(name, frozenset(scopes), "tok-" + name)


@pytest.fixture
def store():
    return TokenStore()
