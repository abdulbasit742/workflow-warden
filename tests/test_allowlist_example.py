from __future__ import annotations

import json
from pathlib import Path


def test_allowlist_example_matches_documented_contract() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    data = json.loads((repo_root / "examples" / "allowlist.example.json").read_text())

    assert data["version"] == 1
    assert isinstance(data["suppressions"], list)
    assert data["suppressions"]

    for suppression in data["suppressions"]:
        assert suppression["rule_id"]
        assert suppression["path"].startswith(".github/workflows/")
        assert suppression["justification"].strip()
        if "expires_on" in suppression:
            parts = suppression["expires_on"].split("-")
            assert len(parts) == 3
            year, month, day = parts
            assert len(year) == 4
            assert len(month) == 2
            assert len(day) == 2
