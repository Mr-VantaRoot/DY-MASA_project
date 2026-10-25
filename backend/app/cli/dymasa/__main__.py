"""Entry point for ``python -m app.cli.dymasa``."""

from __future__ import annotations

import sys

from .bootstrap import bootstrap


def main() -> int:
    try:
        bootstrap()
        from .cli import main as cli_main
    except Exception as exc:
        print(f"DY-MASA startup failed: {exc}", file=sys.stderr)
        return 1
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
