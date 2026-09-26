import re
from typing import List, Dict, Any, Optional
from ..analysis.schemas import RiskFinding
from .classifier import is_infrastructure_file

def scan_infrastructure_changes(files: List[Dict[str, Any]]) -> List[RiskFinding]:
    """Scan infrastructure definitions (k8s, docker, compose, terraform) for reliability & availability risks."""
    findings: List[RiskFinding] = []
    finding_counter = 1

    for file_info in files:
        filename = file_info.get("filename", "")
        if not is_infrastructure_file(filename):
            continue

        patch = file_info.get("patch", "")
        content = file_info.get("content", "")
        text = patch if patch else content
        if not text:
            continue

        lines = text.splitlines()

        # Track diff removals and additions for paired comparison
        removed_replicas = None
        added_replicas = None
        removed_cpu = None
        added_cpu = None
        removed_mem = None
        added_mem = None

        for idx, line in enumerate(lines, start=1):
            raw = line.strip()

            # Check replica reductions in diff
            if line.startswith("-"):
                rep_match = re.search(r'replicas\s*:\s*(\d+)', line)
                if rep_match:
                    removed_replicas = int(rep_match.group(1))
                cpu_match = re.search(r'cpu\s*:\s*["\']?([0-9m]+)["\']?', line)
                if cpu_match:
                    removed_cpu = cpu_match.group(1)
                mem_match = re.search(r'memory\s*:\s*["\']?([0-9a-zA-Z]+)["\']?', line)
                if mem_match:
                    removed_mem = mem_match.group(1)

            elif line.startswith("+") or not patch:
                clean_line = line[1:].strip() if line.startswith("+") else line.strip()
                rep_match = re.search(r'replicas\s*:\s*(\d+)', clean_line)
                if rep_match:
                    added_replicas = int(rep_match.group(1))

                cpu_match = re.search(r'cpu\s*:\s*["\']?([0-9m]+)["\']?', clean_line)
                if cpu_match:
                    added_cpu = cpu_match.group(1)

                mem_match = re.search(r'memory\s*:\s*["\']?([0-9a-zA-Z]+)["\']?', clean_line)
                if mem_match:
                    added_mem = mem_match.group(1)

                # Health check / probe removals or alterations
                if re.search(r'(livenessProbe|readinessProbe|startupProbe)\s*:', clean_line):
                    findings.append(RiskFinding(
                        id=f"finding-infra-{finding_counter:03d}",
                        category="infrastructure",
                        type="health_check_change",
                        severity_hint="medium",
                        confidence=0.92,
                        evidence=clean_line[:120],
                        file=filename,
                        line=idx,
                        changed=True,
                        description=(
                            "Kubernetes container health probe configuration modified. "
                            "Misconfigured probe timeouts or initial delays can cause continuous pod restart loops or traffic starvation."
                        )
                    ))
                    finding_counter += 1

                # Healthcheck disabled
                if re.search(r'HEALTHCHECK\s+NONE', clean_line, re.IGNORECASE):
                    findings.append(RiskFinding(
                        id=f"finding-infra-{finding_counter:03d}",
                        category="infrastructure",
                        type="health_check_disabled",
                        severity_hint="high",
                        confidence=0.95,
                        evidence=clean_line[:120],
                        file=filename,
                        line=idx,
                        changed=True,
                        description="Container health checks explicitly disabled. Docker and orchestrators cannot detect locked or deadlocked processes."
                    ))
                    finding_counter += 1

                # Privileged mode
                if re.search(r'privileged\s*:\s*true', clean_line, re.IGNORECASE):
                    findings.append(RiskFinding(
                        id=f"finding-infra-{finding_counter:03d}",
                        category="infrastructure",
                        type="privileged_container",
                        severity_hint="high",
                        confidence=0.95,
                        evidence=clean_line[:120],
                        file=filename,
                        line=idx,
                        changed=True,
                        description="Container configured with root host privileged access. High security and isolation blast radius."
                    ))
                    finding_counter += 1

        # Check paired replica changes
        if added_replicas is not None:
            if added_replicas == 1:
                findings.append(RiskFinding(
                    id=f"finding-infra-{finding_counter:03d}",
                    category="infrastructure",
                    type="single_replica_risk",
                    severity_hint="high",
                    confidence=0.98,
                    evidence=f"replicas: {removed_replicas if removed_replicas is not None else '?'} → 1",
                    file=filename,
                    changed=True,
                    description=(
                        f"Single replica configuration detected (replicas: {added_replicas}). "
                        "Running a single replica eliminates high availability and zero-downtime rolling deploys. "
                        "Any container restart, image pull delay, or node rescheduling produces immediate 503 outages."
                    ),
                    metadata={"target_replicas": added_replicas, "previous_replicas": removed_replicas}
                ))
                finding_counter += 1
            elif removed_replicas is not None and added_replicas < removed_replicas:
                findings.append(RiskFinding(
                    id=f"finding-infra-{finding_counter:03d}",
                    category="infrastructure",
                    type="reduced_redundancy",
                    severity_hint="medium",
                    confidence=0.95,
                    evidence=f"replicas: {removed_replicas} → {added_replicas}",
                    file=filename,
                    changed=True,
                    description=f"Service capacity reduced from {removed_replicas} to {added_replicas} replicas. Risk of queue saturation during traffic surges.",
                    metadata={"target_replicas": added_replicas, "previous_replicas": removed_replicas}
                ))
                finding_counter += 1

        # Check resource limit reductions
        if removed_cpu and added_cpu and removed_cpu != added_cpu:
            findings.append(RiskFinding(
                id=f"finding-infra-{finding_counter:03d}",
                category="infrastructure",
                type="resource_limit_reduction",
                severity_hint="medium",
                confidence=0.90,
                evidence=f"cpu: {removed_cpu} → {added_cpu}",
                file=filename,
                changed=True,
                description=f"CPU allocation reduced from {removed_cpu} to {added_cpu}. May trigger CPU throttling under peak production load.",
                metadata={"old_cpu": removed_cpu, "new_cpu": added_cpu}
            ))
            finding_counter += 1

        if removed_mem and added_mem and removed_mem != added_mem:
            findings.append(RiskFinding(
                id=f"finding-infra-{finding_counter:03d}",
                category="infrastructure",
                type="resource_limit_reduction",
                severity_hint="medium",
                confidence=0.90,
                evidence=f"memory: {removed_mem} → {added_mem}",
                file=filename,
                changed=True,
                description=f"Memory limit reduced from {removed_mem} to {added_mem}. Elevated risk of Linux OOM killer terminating worker pods.",
                metadata={"old_mem": removed_mem, "new_mem": added_mem}
            ))
            finding_counter += 1

    return findings
