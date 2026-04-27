from __future__ import annotations

import datetime as dt
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import ttk
from typing import Dict, List, Optional, Sequence, Tuple

import psutil

from .collector import CollectorConfig, TrafficCollector
from .state import RatePoint, SharedState
from .storage import SQLiteStorage, TrafficRow
from .utils import TS_FORMAT, bps_to_mbps, format_local_ts, parse_local_ts


def list_nics() -> List[str]:
    return sorted(psutil.net_io_counters(pernic=True).keys())


@dataclass(frozen=True)
class UIConfig:
    live_window_s: int = 10 * 60
    refresh_ms: int = 1000
    plot_refresh_ms: int = 2000


class MonitorApp:
    def __init__(self, *, db_path: Path, ui_config: UIConfig = UIConfig()) -> None:
        self._ui_config = ui_config
        self._state = SharedState(live_keep_seconds=max(3600, ui_config.live_window_s * 2))
        self._storage = SQLiteStorage(db_path)

        self._root = tk.Tk()
        self._root.title("\u7f51\u5361\u6d41\u91cf\u76d1\u63a7 (NIC Traffic Monitor)")
        self._root.geometry("1100x720")

        self._selected_nics_lock = threading.Lock()
        self._selected_nics: List[str] = []
        self._tree_items: Dict[str, str] = {}

        self._collector = TrafficCollector(
            storage=self._storage,
            state=self._state,
            config=CollectorConfig(interval_s=1.0),
        )

        self._build_ui()
        self._collector.start()
        self._schedule_updates()

    def run(self) -> None:
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._root.mainloop()

    def _on_close(self) -> None:
        try:
            self._collector.stop()
        finally:
            self._storage.close()
            self._root.destroy()

    def get_selected_nics(self) -> List[str]:
        with self._selected_nics_lock:
            return list(self._selected_nics)

    def _set_selected_nics(self, nics: Sequence[str]) -> None:
        with self._selected_nics_lock:
            self._selected_nics = list(nics)

    def _build_ui(self) -> None:
        root = self._root
        root.columnconfigure(0, weight=0)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        left = ttk.Frame(root, padding=10)
        left.grid(row=0, column=0, sticky="ns")

        right = ttk.Frame(root, padding=10)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)

        # Left: NIC select
        ttk.Label(left, text="\u7f51\u5361\u9009\u62e9\uff08\u53ef\u591a\u9009\uff09").grid(row=0, column=0, sticky="w")

        self._nic_list = tk.Listbox(left, selectmode=tk.EXTENDED, height=18, exportselection=False)
        self._nic_list.grid(row=1, column=0, sticky="nsew", pady=(6, 6))
        left.rowconfigure(1, weight=1)

        btn_row = ttk.Frame(left)
        btn_row.grid(row=2, column=0, sticky="ew")
        btn_row.columnconfigure(0, weight=1)
        btn_row.columnconfigure(1, weight=1)

        ttk.Button(btn_row, text="\u5237\u65b0\u7f51\u5361", command=self._refresh_nics).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(btn_row, text="\u5e94\u7528\u9009\u62e9", command=self._apply_selection).grid(
            row=0, column=1, sticky="ew"
        )

        ttk.Separator(left, orient="horizontal").grid(row=3, column=0, sticky="ew", pady=12)

        # Left: Range controls
        ttk.Label(left, text="\u65f6\u95f4\u8303\u56f4\uff08\u672c\u5730\u65f6\u95f4\uff09").grid(row=4, column=0, sticky="w")

        self._range_mode = tk.StringVar(value="live")
        modes = ttk.Frame(left)
        modes.grid(row=5, column=0, sticky="ew", pady=(6, 6))
        ttk.Radiobutton(
            modes, text="\u5b9e\u65f6", variable=self._range_mode, value="live", command=self._on_mode_change
        ).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            modes, text="\u5386\u53f2", variable=self._range_mode, value="history", command=self._on_mode_change
        ).grid(row=0, column=1, sticky="w", padx=(12, 0))

        ttk.Label(left, text=f"\u5f00\u59cb ({TS_FORMAT})").grid(row=6, column=0, sticky="w", pady=(8, 0))
        self._start_entry = ttk.Entry(left, width=26)
        self._start_entry.grid(row=7, column=0, sticky="ew")

        ttk.Label(left, text=f"\u7ed3\u675f ({TS_FORMAT})").grid(row=8, column=0, sticky="w", pady=(8, 0))
        self._end_entry = ttk.Entry(left, width=26)
        self._end_entry.grid(row=9, column=0, sticky="ew")

        self._history_hint = ttk.Label(
            left, text="\u63d0\u793a\uff1a\u5386\u53f2\u6a21\u5f0f\u70b9\u51fb\u201c\u52a0\u8f7d\u201d\u540e\u66f4\u65b0\u6298\u7ebf\u56fe"
        )
        self._history_hint.grid(row=10, column=0, sticky="w", pady=(6, 0))

        load_row = ttk.Frame(left)
        load_row.grid(row=11, column=0, sticky="ew", pady=(8, 0))
        load_row.columnconfigure(0, weight=1)
        load_row.columnconfigure(1, weight=1)
        ttk.Button(load_row, text="\u52a0\u8f7d", command=self._load_history).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ttk.Button(load_row, text="\u586b\u5145\u6700\u8fd110\u5206\u949f", command=self._fill_last_10m).grid(
            row=0, column=1, sticky="ew"
        )

        ttk.Separator(left, orient="horizontal").grid(row=12, column=0, sticky="ew", pady=12)

        ttk.Label(left, text="\u66f2\u7ebf\u6307\u6807").grid(row=13, column=0, sticky="w")
        self._metric = tk.StringVar(value="total")
        self._metric_combo = ttk.Combobox(
            left, state="readonly", values=["total", "rx", "tx"], textvariable=self._metric, width=20
        )
        self._metric_combo.grid(row=14, column=0, sticky="ew", pady=(6, 0))
        self._metric_combo.bind("<<ComboboxSelected>>", self._on_metric_change)
        ttk.Label(left, text="total = RX + TX (Mbps)").grid(row=15, column=0, sticky="w", pady=(4, 0))

        ttk.Separator(left, orient="horizontal").grid(row=16, column=0, sticky="ew", pady=12)

        self._status = tk.StringVar(value=f"DB: {self._storage.db_path} (\u9ed8\u8ba4\u8bb0\u5f55\u5168\u90e8\u7f51\u5361)")
        ttk.Label(left, textvariable=self._status, wraplength=260, justify="left").grid(row=17, column=0, sticky="w")

        self._refresh_nics()

        # Right: Current table + plot
        ttk.Label(right, text="\u5f53\u524d\u6d41\u91cf (Mbps)").grid(row=0, column=0, sticky="w")

        self._tree = ttk.Treeview(right, columns=("rx", "tx"), show=("tree", "headings"), height=6)
        self._tree.heading("#0", text="NIC")
        self._tree.column("#0", width=260, anchor="w")
        self._tree.heading("rx", text="RX (Mbps)")
        self._tree.heading("tx", text="TX (Mbps)")
        self._tree.column("rx", width=120, anchor="e")
        self._tree.column("tx", width=120, anchor="e")
        self._tree.grid(row=1, column=0, sticky="ew", pady=(6, 10))

        ttk.Label(right, text="\u6298\u7ebf\u56fe").grid(row=2, column=0, sticky="w")

        plot_frame = ttk.Frame(right)
        plot_frame.grid(row=3, column=0, sticky="nsew")
        plot_frame.columnconfigure(0, weight=1)
        plot_frame.rowconfigure(0, weight=1)
        plot_frame.rowconfigure(1, weight=0)

        import matplotlib

        matplotlib.use("TkAgg")
        import matplotlib.dates as mdates
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
        from matplotlib.figure import Figure

        self._mdates = mdates
        self._fig = Figure(figsize=(8, 5), dpi=100)
        self._ax = self._fig.add_subplot(111)
        self._ax.set_xlabel("Time")
        self._ax.set_ylabel("Mbps")
        self._ax.grid(True, alpha=0.3)
        self._ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))

        self._canvas = FigureCanvasTkAgg(self._fig, master=plot_frame)
        self._canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")
        toolbar_frame = ttk.Frame(plot_frame)
        toolbar_frame.grid(row=1, column=0, sticky="ew")
        self._toolbar = NavigationToolbar2Tk(self._canvas, toolbar_frame)
        self._toolbar.update()

        self._history_rows: Optional[List[TrafficRow]] = None

    def _schedule_updates(self) -> None:
        self._root.after(self._ui_config.refresh_ms, self._update_current_table)
        self._root.after(self._ui_config.plot_refresh_ms, self._update_plot)

    def _refresh_nics(self) -> None:
        current = list_nics()
        prev_selected = set(self.get_selected_nics())

        self._nic_list.delete(0, tk.END)
        for nic in current:
            self._nic_list.insert(tk.END, nic)

        for idx, nic in enumerate(current):
            if nic in prev_selected:
                self._nic_list.selection_set(idx)

        if not prev_selected and current:
            self._nic_list.selection_set(0)
            self._apply_selection()

    def _apply_selection(self) -> None:
        selected = [self._nic_list.get(i) for i in self._nic_list.curselection()]
        self._set_selected_nics(selected)
        if selected:
            self._status.set(
                f"\u5df2\u9009\u62e9\u7f51\u5361\uff1a{', '.join(selected)} | DB: {self._storage.db_path} (\u8bb0\u5f55\u5168\u90e8\u7f51\u5361)"
            )
        else:
            self._status.set(f"\u672a\u9009\u62e9\u7f51\u5361\uff0c\u8bf7\u5148\u9009\u62e9\u9700\u8981\u67e5\u770b\u7684\u7f51\u5361 | DB: {self._storage.db_path}")

    def _on_mode_change(self) -> None:
        self._history_rows = None
        self._update_plot(force=True)

    def _on_metric_change(self, _event: tk.Event[tk.Misc]) -> None:
        self._update_plot(force=True)

    def _fill_last_10m(self) -> None:
        end = dt.datetime.now().astimezone()
        start = end - dt.timedelta(minutes=10)
        self._start_entry.delete(0, tk.END)
        self._start_entry.insert(0, start.strftime(TS_FORMAT))
        self._end_entry.delete(0, tk.END)
        self._end_entry.insert(0, end.strftime(TS_FORMAT))
        self._range_mode.set("history")
        self._on_mode_change()

    def _load_history(self) -> None:
        nics = self.get_selected_nics()
        if not nics:
            self._status.set("\u8bf7\u5148\u9009\u62e9\u81f3\u5c11\u4e00\u4e2a\u7f51\u5361\uff0c\u518d\u52a0\u8f7d\u5386\u53f2\u6570\u636e\u3002")
            return

        ts_start = parse_local_ts(self._start_entry.get())
        ts_end = parse_local_ts(self._end_entry.get())
        if ts_start is None or ts_end is None or ts_start > ts_end:
            self._status.set("\u65f6\u95f4\u683c\u5f0f\u4e0d\u6b63\u786e\uff0c\u6216\u5f00\u59cb\u65f6\u95f4\u665a\u4e8e\u7ed3\u675f\u65f6\u95f4\u3002")
            return

        rows = self._storage.query_range(nics=nics, ts_start=ts_start, ts_end=ts_end)
        self._history_rows = rows
        self._range_mode.set("history")
        self._status.set(
            f"\u5df2\u52a0\u8f7d\u5386\u53f2\u6570\u636e\uff1a{len(rows)} \u884c\uff08{format_local_ts(ts_start)} ~ {format_local_ts(ts_end)}\uff09"
        )
        self._update_plot(force=True)

    def _update_current_table(self) -> None:
        try:
            nics = self.get_selected_nics()
            current = self._state.get_current(nics)
            desired_nics = set(nics)

            for nic in list(self._tree_items):
                if nic in desired_nics:
                    continue
                self._tree.delete(self._tree_items.pop(nic))

            for nic in nics:
                values = self._tree_values(current.get(nic))
                item_id = self._tree_items.get(nic)
                if item_id is None:
                    item_id = self._tree.insert("", tk.END, text=nic, values=values)
                    self._tree_items[nic] = item_id
                else:
                    self._tree.item(item_id, text=nic, values=values)
                    self._tree.move(item_id, "", tk.END)
        finally:
            self._root.after(self._ui_config.refresh_ms, self._update_current_table)

    def _tree_values(self, point: Optional[RatePoint]) -> Tuple[str, str]:
        if point is None:
            return ("0.000", "0.000")
        return (f"{bps_to_mbps(point.rx_bps):.3f}", f"{bps_to_mbps(point.tx_bps):.3f}")

    def _metric_bps(self, rx_bps: float, tx_bps: float, metric: str) -> float:
        if metric == "rx":
            return float(rx_bps)
        if metric == "tx":
            return float(tx_bps)
        return float(rx_bps + tx_bps)

    def _to_plot_point(self, ts: int, bps: float) -> Tuple[dt.datetime, float]:
        local_dt = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).astimezone()
        return (local_dt, bps_to_mbps(bps))

    def _rows_to_series(self, rows: List[TrafficRow], metric: str) -> Dict[str, List[Tuple[dt.datetime, float]]]:
        out: Dict[str, List[Tuple[dt.datetime, float]]] = {}
        for r in rows:
            series = out.setdefault(r.nic, [])
            series.append(self._to_plot_point(r.ts, self._metric_bps(r.rx_bps, r.tx_bps, metric)))
        return out

    def _live_to_series(
        self, points: Dict[str, List[RatePoint]], metric: str
    ) -> Dict[str, List[Tuple[dt.datetime, float]]]:
        out: Dict[str, List[Tuple[dt.datetime, float]]] = {}
        for nic, series in points.items():
            out[nic] = [self._to_plot_point(p.ts, self._metric_bps(p.rx_bps, p.tx_bps, metric)) for p in series]
        return out

    def _update_plot(self, *, force: bool = False) -> None:
        try:
            nics = self.get_selected_nics()
            if not nics:
                return

            metric = self._metric.get()

            if self._range_mode.get() == "history":
                rows = self._history_rows
                if rows is None:
                    return
                series_by_nic = self._rows_to_series(rows, metric)
                title = "\u5386\u53f2"
            else:
                live = self._state.get_live_series(nics, last_seconds=self._ui_config.live_window_s)
                series_by_nic = self._live_to_series(live, metric)
                title = f"\u5b9e\u65f6\uff08\u6700\u8fd1 {self._ui_config.live_window_s // 60} \u5206\u949f\uff09"

            self._ax.clear()
            self._ax.grid(True, alpha=0.3)
            self._ax.set_xlabel("Time")
            self._ax.set_ylabel("Mbps")
            self._ax.set_title(f"{title} | metric={metric}")
            self._ax.xaxis.set_major_formatter(self._mdates.DateFormatter("%H:%M:%S"))

            for nic in nics:
                series = series_by_nic.get(nic, [])
                if not series:
                    continue
                x = [t for t, _ in series]
                y = [v for _, v in series]
                self._ax.plot(x, y, label=nic, linewidth=1.6)

            if any(series_by_nic.get(n) for n in nics):
                self._ax.legend(loc="upper left", fontsize=8, ncol=1)

            self._fig.tight_layout()
            self._canvas.draw_idle()
        finally:
            self._root.after(self._ui_config.plot_refresh_ms, self._update_plot)
