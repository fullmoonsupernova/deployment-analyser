import json
from pathlib import Path
from typing import List
from ..analysis.schemas import RiskFinding, HistoricalIncidentMatch

DB_PATH = Path(__file__).resolve().parent / "database.json"

class IncidentMatcher:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.incidents = self._load_incidents()

    def _load_incidents(self) -> list:
        if not self.db_path.exists():
            return []
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def match(self, findings: List[RiskFinding]) -> List[HistoricalIncidentMatch]:
        """Deterministically match discovered risk findings against historical incident patterns."""
        if not findings or not self.incidents:
            return []

        finding_types = {f.type.lower() for f in findings}
        finding_categories = {f.category.lower() for f in findings}
        
        # Build mapping of pattern to finding IDs
        pattern_to_finding_ids = {}
        for f in findings:
            keys = [f.type.lower(), f.category.lower()]
            for k in keys:
                if k not in pattern_to_finding_ids:
                    pattern_to_finding_ids[k] = []
                pattern_to_finding_ids[k].append(f.id)

        matches = []
        for inc in self.incidents:
            inc_patterns = [p.lower() for p in inc.get("patterns", [])]
            if not inc_patterns:
                continue

            matched_patterns = []
            matched_finding_ids = set()

            for pattern in inc_patterns:
                # Check exact or partial pattern match against finding types
                matched = False
                for ft in finding_types:
                    if pattern in ft or ft in pattern:
                        matched = True
                        for fid in pattern_to_finding_ids.get(ft, []):
                            matched_finding_ids.add(fid)
                if not matched:
                    for fc in finding_categories:
                        if pattern in fc or fc in pattern:
                            matched = True
                            for fid in pattern_to_finding_ids.get(fc, []):
                                matched_finding_ids.add(fid)

                if matched:
                    matched_patterns.append(pattern)

            if matched_patterns:
                score = round(len(matched_patterns) / len(inc_patterns), 2)
                matches.append(HistoricalIncidentMatch(
                    incident_id=inc["id"],
                    title=inc.get("title", inc["id"]),
                    matched_patterns=matched_patterns,
                    failure_summary=inc.get("failure", ""),
                    historic_impact=inc.get("impact", ""),
                    severity=inc.get("severity", "medium"),
                    match_score=score,
                    matched_findings=list(matched_finding_ids)
                ))

        # Sort by match_score descending, then severity
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        matches.sort(
            key=lambda m: (m.match_score, severity_rank.get(m.severity.lower(), 0)),
            reverse=True
        )
        return matches
