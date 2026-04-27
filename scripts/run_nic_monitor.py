from __future__ import annotations

from pathlib import Path

from nic_monitor.ui_tk import MonitorApp


def main() -> None:
    db_path = Path.cwd() / "data" / "nic_traffic.sqlite"
    app = MonitorApp(db_path=db_path)
    app.run()


if __name__ == "__main__":
    main()

