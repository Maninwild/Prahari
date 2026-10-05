import sqlite3
import json
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL, decision TEXT NOT NULL, result TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS enforcement (event_id TEXT PRIMARY KEY, scan_id TEXT UNIQUE NOT NULL, mode TEXT NOT NULL, action TEXT NOT NULL)"
            )

    def event(self, event):
        values = (event.event_id, event.scan_id, event.mode, event.action)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT event_id,scan_id,mode,action FROM enforcement WHERE event_id=? OR scan_id=?",
                (event.event_id, event.scan_id),
            ).fetchone()
            if existing:
                if existing != values:
                    raise ValueError("Conflicting acknowledgement")
                return
            db.execute("INSERT INTO enforcement VALUES (?,?,?,?)", values)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def save(self, result, kind):
        with self.connect() as db:
            db.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?)",
                (
                    result.scan_id,
                    result.created_at,
                    kind,
                    result.decision,
                    result.model_dump_json(),
                ),
            )

    def list(self, decision, limit, offset):
        where = " WHERE decision=?" if decision else ""
        args = [decision] if decision else []
        with self.connect() as db:
            total = db.execute("SELECT count(*) FROM scans" + where, args).fetchone()[0]
            rows = db.execute(
                "SELECT id,created,kind,decision FROM scans"
                + where
                + " ORDER BY created DESC LIMIT ? OFFSET ?",
                args + [limit, offset],
            ).fetchall()
        return {
            "total": total,
            "items": [
                dict(zip(["scan_id", "created_at", "input_type", "decision"], r))
                for r in rows
            ],
        }

    def get(self, scan_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT result FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            events = db.execute(
                "SELECT event_id,mode,action FROM enforcement WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        if not row:
            return None
        result = json.loads(row[0])
        result["enforcement_events"] = [
            dict(zip(["event_id", "mode", "action"], event)) for event in events
        ]
        return result

    def summary(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT decision,count(*) FROM scans GROUP BY decision"
            ).fetchall()
            actions = dict(
                db.execute(
                    "SELECT action,count(*) FROM enforcement GROUP BY action"
                ).fetchall()
            )
            partial = db.execute(
                "SELECT count(*) FROM scans WHERE json_extract(result, '$.status')='partial'"
            ).fetchone()[0]
            mean_risk = db.execute(
                "SELECT avg(json_extract(result, '$.risk_score')) FROM scans"
            ).fetchone()[0]
            categories = dict(db.execute("""
                SELECT json_extract(f.value, '$.category'), count(DISTINCT s.id)
                FROM scans s, json_each(s.result, '$.findings') f
                WHERE json_extract(f.value, '$.evidence_kind')='rule'
                GROUP BY json_extract(f.value, '$.category')
            """).fetchall())
            daily = db.execute("""
                SELECT substr(created,1,10), decision, count(*) FROM scans
                WHERE created >= date('now','-6 days')
                GROUP BY substr(created,1,10), decision ORDER BY 1
            """).fetchall()
        counts = {"Allow": 0, "Review": 0, "Block": 0, **dict(rows)}
        from datetime import datetime, timedelta, timezone

        today = datetime.now(timezone.utc).date()
        trend = {
            (today - timedelta(days=i)).isoformat(): {
                "Allow": 0,
                "Review": 0,
                "Block": 0,
            }
            for i in range(6, -1, -1)
        }
        for day, decision, count in daily:
            if day in trend:
                trend[day][decision] = count
        return {
            "total": sum(counts.values()),
            "decisions": counts,
            "enforced_blocks": actions.get("blocked", 0),
            "enforcement": actions,
            "partial_scans": partial,
            "mean_risk": round(mean_risk, 2) if mean_risk is not None else None,
            "rule_categories": {
                category: categories.get(category, 0)
                for category in (
                    "phishing",
                    "sqli",
                    "xss",
                    "command_injection",
                    "path_traversal",
                )
            },
            "daily": [
                {"date": day, "decisions": values, "total": sum(values.values())}
                for day, values in trend.items()
            ],
        }
