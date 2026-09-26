from pathlib import Path
import re

DEPENDENCY_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "pipfile.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "gemfile.lock",
    "composer.json",
}

INFRASTRUCTURE_PATTERNS = [
    re.compile(r'(^|/)dockerfile[a-zA-Z0-9._-]*$', re.IGNORECASE),
    re.compile(r'(^|/)docker-compose(\.[a-zA-Z0-9_-]+)?\.ya?ml$', re.IGNORECASE),
    re.compile(r'.*\.tf(\.json)?$'),
    re.compile(r'.*\.tfvars$'),
    re.compile(r'(^|/)(k8s|kubernetes|helm|deploy|deployments|manifests)/.*\.ya?ml$', re.IGNORECASE),
    re.compile(r'.*(deployment|statefulset|daemonset|ingress|service|hpa|cronjob|helm|chart)\.ya?ml$', re.IGNORECASE),
    re.compile(r'(^|/)Chart\.ya?ml$', re.IGNORECASE),
    re.compile(r'(^|/)values(\.[a-zA-Z0-9_-]+)?\.ya?ml$', re.IGNORECASE),
]

MIGRATION_PATTERNS = [
    re.compile(r'(^|/)(migrations|alembic|prisma/migrations|db/migrations|database/migrations|flyway)/', re.IGNORECASE),
    re.compile(r'.*(migrate|migration|schema|ddl|changelog).*\.sql$', re.IGNORECASE),
    re.compile(r'(^|/)alembic/versions/.*\.py$'),
    re.compile(r'.*schema\.prisma$'),
]

CONFIGURATION_PATTERNS = [
    re.compile(r'(^|/)\.env(\.[a-zA-Z0-9._-]+)?$'),
    re.compile(r'(^|/)application(\.[a-zA-Z0-9._-]+)?\.ya?ml$', re.IGNORECASE),
    re.compile(r'(^|/)application(\.[a-zA-Z0-9._-]+)?\.properties$', re.IGNORECASE),
    re.compile(r'(^|/)(config|settings|conf)/.*', re.IGNORECASE),
    re.compile(r'.*\.(conf|ini|cfg|toml|yaml|yml)$', re.IGNORECASE),
]

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".cs",
    ".rb", ".php", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".scala",
    ".kt", ".kts", ".swift", ".m", ".sh", ".bash", ".zsh"
}

def is_migration_file(filepath: str) -> bool:
    norm = filepath.replace("\\", "/").lower()
    for pattern in MIGRATION_PATTERNS:
        if pattern.search(norm):
            return True
    if norm.endswith(".sql"):
        return True
    return False

def is_dependency_file(filepath: str) -> bool:
    basename = Path(filepath).name.lower()
    return basename in DEPENDENCY_FILENAMES

def is_infrastructure_file(filepath: str) -> bool:
    norm = filepath.replace("\\", "/")
    for pattern in INFRASTRUCTURE_PATTERNS:
        if pattern.search(norm):
            return True
    return False

def is_config_file(filepath: str) -> bool:
    if is_infrastructure_file(filepath) or is_dependency_file(filepath) or is_migration_file(filepath):
        return False
    norm = filepath.replace("\\", "/")
    for pattern in CONFIGURATION_PATTERNS:
        if pattern.search(norm):
            return True
    return False

def is_code_file(filepath: str) -> bool:
    if is_migration_file(filepath) or is_dependency_file(filepath) or is_infrastructure_file(filepath):
        return False
    suffix = Path(filepath).suffix.lower()
    return suffix in CODE_EXTENSIONS

def classify_file(filepath: str) -> str:
    """Classifies a repo file into code, dependencies, infrastructure, configuration, database, doc, or other."""
    if is_migration_file(filepath):
        return "database_migration"
    if is_dependency_file(filepath):
        return "dependency"
    if is_infrastructure_file(filepath):
        return "infrastructure"
    if is_config_file(filepath):
        return "configuration"
    if is_code_file(filepath):
        return "code"
    
    basename = Path(filepath).name.lower()
    if basename.startswith("readme") or filepath.lower().startswith("docs/"):
        return "documentation"
    return "other"
