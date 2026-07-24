"""Storage abstraction for scan state and reports."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from .models import ScanResult


class StorageError(RuntimeError):
    """Raised when scan storage fails."""


class LocalStorage:
    """Filesystem-backed storage for the MVP."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.output_dir.is_symlink():
            raise StorageError("output directory must not be a symlink")

    def load_previous_scan(self, path: Path | None = None) -> ScanResult | None:
        scan_path = path or self.output_dir / "previous-scan.json"
        if not scan_path.exists():
            return None
        if scan_path.is_symlink():
            raise StorageError("previous scan path must not be a symlink")
        try:
            data = json.loads(scan_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise StorageError(f"previous scan is not valid JSON: {scan_path}") from exc
        if not isinstance(data, dict):
            raise StorageError("previous scan JSON must be an object")
        return ScanResult.from_dict(data)

    def save_current_scan(self, scan: ScanResult) -> Path:
        path = self.output_dir / "current-scan.json"
        self._write_json(path, scan.to_dict())
        return path

    def save_comparison(self, comparison: dict[str, Any]) -> Path:
        path = self.output_dir / "comparison-summary.json"
        self._write_json(path, comparison)
        return path

    def save_report(self, report_markdown: str, filename: str = "report.md") -> Path:
        path = self.output_dir / filename
        self._write_text(path, report_markdown)
        return path

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        self._write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def _write_text(self, path: Path, text: str) -> None:
        if path.exists() and path.is_symlink():
            raise StorageError(f"refusing to write through symlink: {path}")
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.output_dir,
            delete=False,
        ) as handle:
            handle.write(text)
            temp_path = Path(handle.name)
        temp_path.replace(path)
