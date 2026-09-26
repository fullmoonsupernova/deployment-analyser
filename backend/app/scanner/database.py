import re
from typing import List, Dict, Any, Optional
from ..analysis.schemas import RiskFinding
from .classifier import is_migration_file

SQL_PATTERNS = [
    # DROP COLUMN
    (
        re.compile(r'\bALTER\s+TABLE\s+([^\s;]+)\s+DROP\s+(?:COLUMN\s+)?([^\s;,]+)', re.IGNORECASE),
        "destructive_database_change",
        "high",
        "Destructive schema change: Column '{col}' dropped from table '{tbl}'. Old application instances referencing this column will fail during rolling deployment."
    ),
    # DROP TABLE
    (
        re.compile(r'\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([^\s;,]+)', re.IGNORECASE),
        "destructive_database_change",
        "critical",
        "Destructive schema change: Table '{tbl}' dropped completely. Any live query referencing this table will result in immediate 500 errors."
    ),
    # RENAME COLUMN
    (
        re.compile(r'\bALTER\s+TABLE\s+([^\s;]+)\s+RENAME\s+(?:COLUMN\s+)?([^\s;]+)\s+TO\s+([^\s;,]+)', re.IGNORECASE),
        "schema_compatibility",
        "high",
        "Column rename on table '{tbl}' from '{col}' to '{new_col}'. Causes instant breakage for concurrently running pods expecting the old column name."
    ),
    # RENAME TABLE
    (
        re.compile(r'\bRENAME\s+TABLE\s+([^\s;]+)\s+TO\s+([^\s;,]+)', re.IGNORECASE),
        "schema_compatibility",
        "high",
        "Table rename from '{tbl}' to '{new_tbl}'. Rolling pods expecting the old table will immediately fail."
    ),
    # ADD COLUMN ... NOT NULL without DEFAULT
    (
        re.compile(r'\bALTER\s+TABLE\s+([^\s;]+)\s+ADD\s+(?:COLUMN\s+)?([^\s;]+)\s+([^\s;,]+)\s+NOT\s+NULL(?!\s+DEFAULT)', re.IGNORECASE),
        "not_null_addition",
        "high",
        "Column '{col}' added with NOT NULL constraint without DEFAULT value on table '{tbl}'. Insert queries from old code will violate non-null constraint."
    ),
    # ALTER/MODIFY COLUMN type change
    (
        re.compile(r'\bALTER\s+TABLE\s+([^\s;]+)\s+(?:ALTER|MODIFY)\s+(?:COLUMN\s+)?([^\s;]+)\s+TYPE\s+([^\s;,]+)', re.IGNORECASE),
        "schema_type_change",
        "medium",
        "Column '{col}' on table '{tbl}' modified type to '{type}'. May cause serialization or casting failures for existing connections."
    ),
    # DROP INDEX
    (
        re.compile(r'\bDROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?([^\s;,]+)', re.IGNORECASE),
        "performance_index_removal",
        "medium",
        "Index '{idx}' dropped. May cause query performance degradation, full table scans, or lock escalation under peak traffic."
    ),
    # DELETE without WHERE or broad DELETE
    (
        re.compile(r'\bDELETE\s+FROM\s+([^\s;]+)(?:\s*;|\s+WHERE\s+1\s*=\s*1)', re.IGNORECASE),
        "destructive_data_migration",
        "critical",
        "Mass DELETE operation without restrictive WHERE clause on table '{tbl}'. Risk of irreversible data loss."
    ),
    # Large UPDATE without WHERE
    (
        re.compile(r'\bUPDATE\s+([^\s;]+)\s+SET\s+(?:(?!WHERE)[\s\S])+;$', re.IGNORECASE | re.MULTILINE),
        "broad_data_update",
        "high",
        "Unbounded UPDATE operation across entire table '{tbl}' without WHERE clause. May hold table locks and cause transaction timeouts."
    ),
]

# Python Alembic patterns
ALEMBIC_PATTERNS = [
    (
        re.compile(r'op\.drop_column\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
        "destructive_database_change",
        "high",
        "Alembic migration drops column '{col}' from table '{tbl}'. Breaks backward compatibility for concurrently running instances."
    ),
    (
        re.compile(r'op\.drop_table\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
        "destructive_database_change",
        "critical",
        "Alembic migration drops table '{tbl}'. Queries from existing pods will fail."
    ),
    (
        re.compile(r'op\.alter_column\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"].*nullable\s*=\s*False', re.IGNORECASE),
        "not_null_addition",
        "high",
        "Alembic migration makes column '{col}' non-nullable on table '{tbl}'."
    ),
]

def scan_database_changes(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Scan migration files and database queries for destructive or risky schema changes."""
    findings: List[RiskFinding] = []
    finding_counter = 1
    dropped_columns = []

    for file_info in files:
        filename = file_info.get("filename", "")
        patch = file_info.get("patch", "")
        content = file_info.get("content", "")
        
        # We analyze both patch (for diff) and content if available
        is_migration = is_migration_file(filename)
        
        # Scan lines of diff
        text_to_scan = patch if patch else content
        if not text_to_scan:
            continue

        lines = text_to_scan.split("\n")
        for line_idx, raw_line in enumerate(lines, start=1):
            # Focus on added or modified lines in diffs (starting with '+'), or all lines in migration content
            line = raw_line
            if patch and not (raw_line.startswith("+") and not raw_line.startswith("+++")):
                continue
            if patch and raw_line.startswith("+"):
                line = raw_line[1:].strip()

            # 1. SQL checks (in migration files or sql files)
            if is_migration or filename.endswith(".sql"):
                # SQL regexes
                for pattern, finding_type, severity, desc_template in SQL_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        groups = match.groups()
                        tbl = groups[0] if len(groups) > 0 else "unknown"
                        col = groups[1] if len(groups) > 1 else ""
                        new_col = groups[2] if len(groups) > 2 else ""
                        idx = groups[0] if len(groups) > 0 else ""
                        
                        desc = desc_template.format(tbl=tbl, col=col, new_col=new_col, new_tbl=new_col, idx=idx, type=new_col)
                        
                        if finding_type == "destructive_database_change" and col:
                            dropped_columns.append({"table": tbl, "column": col, "file": filename, "line": line_idx})

                        findings.append(RiskFinding(
                            id=f"finding-db-{finding_counter:03d}",
                            category="database",
                            type=finding_type,
                            severity_hint=severity,
                            confidence=0.98,
                            evidence=line[:200],
                            file=filename,
                            line=line_idx,
                            changed=True,
                            description=desc,
                            metadata={"table": tbl, "column": col}
                        ))
                        finding_counter += 1

                # Alembic checks
                for pattern, finding_type, severity, desc_template in ALEMBIC_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        groups = match.groups()
                        tbl = groups[0] if len(groups) > 0 else ""
                        col = groups[1] if len(groups) > 1 else ""
                        desc = desc_template.format(tbl=tbl, col=col)
                        
                        if "drop_column" in pattern.pattern:
                            dropped_columns.append({"table": tbl, "column": col, "file": filename, "line": line_idx})

                        findings.append(RiskFinding(
                            id=f"finding-db-{finding_counter:03d}",
                            category="database",
                            type=finding_type,
                            severity_hint=severity,
                            confidence=0.98,
                            evidence=line[:200],
                            file=filename,
                            line=line_idx,
                            changed=True,
                            description=desc,
                            metadata={"table": tbl, "column": col}
                        ))
                        finding_counter += 1

    # Check for expand/contract compatibility hazards across non-migration code
    # If a column was dropped, did code also delete or reference it without an expand/contract phase?
    if dropped_columns:
        for drop_info in dropped_columns:
            findings.append(RiskFinding(
                id=f"finding-db-{finding_counter:03d}",
                category="database",
                type="expand_contract_hazard",
                severity_hint="critical",
                confidence=0.95,
                evidence=f"Column '{drop_info['column']}' dropped in {drop_info['file']}:{drop_info['line']} without phased expand/contract deployment",
                file=drop_info["file"],
                line=drop_info["line"],
                changed=True,
                description=(
                    f"Expand/contract hazard: Table '{drop_info['table']}' loses column '{drop_info['column']}'. "
                    "In a rolling release, existing active containers will issue queries expecting this column, causing immediate 5xx failures. "
                    "Requires multi-phase deployment: (1) stop reading/writing column, (2) deploy app, (3) drop column."
                ),
                metadata=drop_info
            ))
            finding_counter += 1

    return findings
