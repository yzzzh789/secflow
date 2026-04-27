from __future__ import annotations

from pathlib import Path

from .ui_tk import MonitorApp


def main() -> None:
    db_path = Path.cwd() / "data" / "nic_traffic.sqlite"
    MonitorApp(db_path=db_path).run()


if __name__ == "__main__":
    main()
