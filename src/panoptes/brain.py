"""Persistent scan memory ("the brain").

A small SQLite store that remembers targets, scan runs and findings across
invocations. This powers:

  * **dedupe across runs** — a finding seen before is "known", not "new";
  * **retest / diff** — what appeared or disappeared since the last run;
  * **history** — when each issue was first and last observed.

The brain is intentionally schema-light and dependency-free (stdlib sqlite3).
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    findings    INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    plugin      TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    url         TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    last_run    INTEGER,
    times_seen  INTEGER DEFAULT 1,
    status      TEXT DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
"""


@dataclass
class RunDiff:
    """What changed for a target between the previous state and this run."""

    new: List[Finding]
    known: List[Finding]
    resolved: List[Dict[str, str]]  # rows seen before but not in this run

    def to_dict(self) -> Dict[str, object]:
        return {
            "new": [f.to_dict() for f in self.new],
            "known": [f.to_dict() for f in self.known],
            "resolved": self.resolved,
            "counts": {
                "new": len(self.new),
                "known": len(self.known),
                "resolved": len(self.resolved),
            },
        }


class Brain:
    def __init__(self, path: str = ".panoptes/brain.db") -> None:
        self.path = path
        if path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(Path(path).expanduser()) if path != ":memory:" else path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # -- runs ---------------------------------------------------------------
    def start_run(self, target: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(target, started_at) VALUES (?, ?)",
            (target, time.time()),
        )
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def finish_run(self, run_id: int, findings: int) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ?, findings = ? WHERE id = ?",
            (time.time(), findings, run_id),
        )
        self.conn.commit()

    def run_count(self, target: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM runs WHERE target = ? AND finished_at IS NOT NULL",
            (target,),
        ).fetchone()
        return int(row["c"])

    # -- findings -----------------------------------------------------------
    def known_fingerprints(self, target: str) -> Set[str]:
        rows = self.conn.execute(
            "SELECT fingerprint FROM findings WHERE target = ?", (target,)
        ).fetchall()
        return {r["fingerprint"] for r in rows}

    def record(self, target: str, findings: List[Finding], run_id: Optional[int] = None) -> RunDiff:
        """Upsert findings; return a diff of new/known/resolved for this target."""
        before = self.known_fingerprints(target)
        current: Set[str] = set()
        new: List[Finding] = []
        known: List[Finding] = []
        now = time.time()

        for f in findings:
            fp = f.fingerprint
            current.add(fp)
            if fp in before:
                known.append(f)
                self.conn.execute(
                    "UPDATE findings SET last_seen = ?, last_run = ?, "
                    "times_seen = times_seen + 1, status = 'open', severity = ? "
                    "WHERE fingerprint = ?",
                    (now, run_id, f.severity.name.lower(), fp),
                )
            else:
                new.append(f)
                self.conn.execute(
                    "INSERT INTO findings(fingerprint, target, plugin, title, severity, "
                    "url, first_seen, last_seen, last_run, times_seen, status) "
                    "VALUES (?,?,?,?,?,?,?,?,?,1,'open')",
                    (fp, target, f.plugin, f.title, f.severity.name.lower(),
                     f.url, now, now, run_id),
                )

        # Resolved = previously open for this target, not seen now.
        resolved_rows = self.conn.execute(
            "SELECT fingerprint, plugin, title, severity, url FROM findings "
            "WHERE target = ? AND status = 'open'",
            (target,),
        ).fetchall()
        resolved: List[Dict[str, str]] = []
        for r in resolved_rows:
            if r["fingerprint"] not in current:
                resolved.append({k: r[k] for k in r.keys()})
                self.conn.execute(
                    "UPDATE findings SET status = 'resolved' WHERE fingerprint = ?",
                    (r["fingerprint"],),
                )
        self.conn.commit()
        return RunDiff(new=new, known=known, resolved=resolved)

    def stats(self, target: str) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings "
            "WHERE target = ? AND status = 'open' GROUP BY severity",
            (target,),
        ).fetchall()
        out = {s.name.lower(): 0 for s in Severity}
        for r in rows:
            out[r["severity"]] = int(r["c"])
        out["runs"] = self.run_count(target)
        return out

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Brain":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
