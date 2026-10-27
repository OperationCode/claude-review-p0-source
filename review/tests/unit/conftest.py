import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "schema"


def load_fixture(kind: str, name: str):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text(encoding="utf-8"))


def fixture_names(kind: str, prefix: str) -> list[str]:
    return sorted(p.stem for p in (FIXTURES / kind).glob(f"{prefix}-*.json"))


@pytest.fixture
def good_envelope():
    return load_fixture("envelope", "good-bundle")
