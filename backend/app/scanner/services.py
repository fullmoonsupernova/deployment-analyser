import re
from typing import List, Dict, Any, Tuple
from ..analysis.schemas import ServiceNode, ServiceEdge

def infer_service_topology(files: List[Dict[str, Any]], detected_external: Dict[str, Dict[str, Any]]) -> Tuple[List[ServiceNode], List[ServiceEdge]]:
    """Deterministically infer service nodes and dependency edges from manifests, code, and config."""
    nodes_map: Dict[str, ServiceNode] = {}
    edges: List[ServiceEdge] = []

    # 1. Base API / Application node
    api_node = ServiceNode(
        id="service-api",
        name="Backend API",
        type="api",
        confidence=0.99,
        metadata={"role": "primary_application_service"}
    )
    nodes_map[api_node.id] = api_node

    frontend_node = ServiceNode(
        id="service-frontend",
        name="Web Frontend / Client",
        type="frontend",
        confidence=0.90,
        metadata={"role": "ingress_caller"}
    )
    nodes_map[frontend_node.id] = frontend_node

    edges.append(ServiceEdge(
        from_node="service-frontend",
        to_node="service-api",
        type="rest_api",
        confidence=0.95
    ))

    # 2. Inspect Docker Compose files for explicit container services
    for file_info in files:
        filename = file_info.get("filename", "").lower()
        if "compose" in filename or "docker-compose" in filename:
            content = file_info.get("content", "") or file_info.get("patch", "")
            # Look for service keys
            # services:
            #   api: ...
            #   worker: ...
            #   postgres: ...
            matches = re.findall(r'^\s{2}([a-zA-Z0-9_\-]+)\s*:', content, re.MULTILINE)
            for svc in matches:
                svc_clean = svc.lower()
                if svc_clean in ["version", "services", "volumes", "networks"]:
                    continue
                node_id = f"service-{svc_clean}"
                stype = "service"
                if any(k in svc_clean for k in ["db", "postgres", "mysql", "mongo"]):
                    stype = "database"
                elif any(k in svc_clean for k in ["redis", "memcache"]):
                    stype = "cache"
                elif "worker" in svc_clean or "celery" in svc_clean:
                    stype = "worker"

                if node_id not in nodes_map:
                    nodes_map[node_id] = ServiceNode(
                        id=node_id,
                        name=svc.title(),
                        type=stype,
                        confidence=0.96,
                        metadata={"source": "docker-compose"}
                    )
                    if stype in ["database", "cache"]:
                        edges.append(ServiceEdge(
                            from_node="service-api",
                            to_node=node_id,
                            type=stype,
                            confidence=0.95
                        ))
                    elif stype == "worker":
                        edges.append(ServiceEdge(
                            from_node=node_id,
                            to_node="service-api",
                            type="internal_rpc",
                            confidence=0.88
                        ))

    # 3. Add detected external services (PostgreSQL, Redis, Stripe, AWS, etc.)
    for key, meta in detected_external.items():
        node_id = f"ext-{key.lower()}"
        if node_id not in nodes_map:
            nodes_map[node_id] = ServiceNode(
                id=node_id,
                name=meta["name"],
                type=meta["type"],
                confidence=0.92,
                metadata={"category": meta["category"]}
            )
            edges.append(ServiceEdge(
                from_node="service-api",
                to_node=node_id,
                type=meta["type"],
                confidence=0.92
            ))

    # Ensure at least a database exists if migrations or DB queries were detected
    has_db = any(n.type == "database" for n in nodes_map.values())
    if not has_db:
        # Check if database migration files exist
        has_migrations = any("migration" in f.get("filename", "").lower() or f.get("filename", "").endswith(".sql") for f in files)
        if has_migrations:
            db_node = ServiceNode(
                id="ext-postgres",
                name="PostgreSQL Database",
                type="database",
                confidence=0.94,
                metadata={"inferred_from": "migration_files"}
            )
            nodes_map[db_node.id] = db_node
            edges.append(ServiceEdge(
                from_node="service-api",
                to_node="ext-postgres",
                type="database",
                confidence=0.95
            ))

    return list(nodes_map.values()), edges
