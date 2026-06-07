from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4


def pytest_configure(config) -> None:
    if config.option.basetemp is None:
        run_id = f"{os.getpid()}-{uuid4().hex[:8]}"
        config.option.basetemp = str(Path.cwd() / f".pytest-run-{run_id}")
