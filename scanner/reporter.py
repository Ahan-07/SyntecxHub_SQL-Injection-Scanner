import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path


class ReportWriter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def _prefix(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self.output_dir / f"scan_{stamp}"

    def write_json(self, report: dict):
        path = self._prefix().with_suffix(".json")
        path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    def write_csv(self, findings):
        path = self._prefix().with_suffix(".csv")

        rows = [asdict(item) for item in findings]

        fieldnames = [
            "url",
            "method",
            "parameter",
            "test_type",
            "confidence",
            "evidence",
            "baseline_status",
            "test_status",
            "baseline_length",
            "test_length",
            "payload",
            "timestamp",
        ]

        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
