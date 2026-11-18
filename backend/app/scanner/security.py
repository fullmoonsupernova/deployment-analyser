import asyncio
import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Set

import httpx

from ..analysis.schemas import SecurityAITriage, SecurityFinding, SecurityScanReport
from ..github.client import GitHubAPIError, GitHubClient
from ..analysis.groq import GroqAnalyzer

MAX_SECURITY_SCAN_FILES = 100
MAX_SECURITY_FILE_BYTES = 500_000
MAX_CONCURRENT_FILE_REQUESTS = 8
MAX_FINDINGS_PER_FILE = 20

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql", ".ts", ".tsx",
    ".cjs", ".mjs", ".vue", ".svelte", ".html",
}
IGNORED_DIRECTORIES = {
    ".git", ".venv", "build", "coverage", "dist", "node_modules",
    "site-packages", "vendor",
}

RULES = (
    (
        "CODE-SQLI",
        "high",
        0.85,
        "Possible SQL injection",
        "A database query appears to construct SQL commands using string formatting, interpolation, or concatenation with dynamic variables.",
        "Use parameterized queries, prepared statements, or ORM parameter binding instead of string concatenation.",
        re.compile(
            r"""(?ix)
            (?:execute|executeQuery|executeUpdate|executemany|query|rawQuery|raw|from_raw_sql|sql)\s*\(\s*f["']
            |(?:execute|query)\s*\([^)\n]*\.format\s*\(
            |(?:execute|executeQuery|executeUpdate|query|rawQuery)\s*\([^)\n]*["'][^"']*["']\s*[\+\%]
            |\.query\s*\(\s*`[^`]*\$\{
            |\btext\s*\(\s*f["']
            |\b(?:select|insert|update|delete)\b[^;\n]*["']\s*[\+\%]\s*[a-zA-Z_]
            |prisma\.\$queryRawUnsafe\s*\(
            |sequelize\.query\s*\([^)\n]*\+
            |createStatement\s*\(\s*\)\.execute(?:Query|Update)\s*\([^)\n]*\+
            |\$pdo->(?:query|exec)\s*\([^)\n]*["'][^"']*["']\s*\.
            |mysqli_query\s*\([^)\n]*["'][^"']*["']\s*\.
            |db\.(?:Query|Exec)\s*\(\s*fmt\.Sprintf\s*\(
            |SqlCommand\s*\(\s*["'][^"']*["']\s*\+
            """
        ),
    ),
    (
        "CODE-CMDI",
        "high",
        0.88,
        "Possible command injection",
        "A system shell command is constructed or executed with an interpreter that can evaluate shell metacharacters.",
        "Avoid shell execution; pass argument lists (shell=False) and validate or sanitize all external inputs.",
        re.compile(
            r"""(?ix)
            \bos\.system\s*\(
            |\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)\n]*shell\s*=\s*True
            |\bos\.popen\s*\(
            |\bos\.spawn[lpev]*\s*\(
            |\bcommands\.get(?:output|statusoutput)\s*\(
            |\bpty\.spawn\s*\(
            |child_process\.(?:exec|execSync)\s*\(
            |child_process\.spawn\s*\([^)\n]*shell\s*:\s*true
            |\b(?:shell_exec|passthru|proc_open|pcntl_exec)\s*\(
            |\bexec\s*\([^)\n]*\$(?:_GET|_POST|_REQUEST|[a-zA-Z_])
            |Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(
            |ProcessBuilder\s*\([^)\n]*\+
            |exec\.Command\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*,\s*["']-[cC]["']
            |Kernel\.open\s*\(\s*["']\|
            |\b(?:system|popen)\s*\([^)\n]*\+
            """
        ),
    ),
    (
        "CODE-UNSAFE-DESERIALIZATION",
        "high",
        0.88,
        "Unsafe deserialization",
        "The code uses a deserializer that may instantiate executable or attacker-controlled objects.",
        "Use a safe data format and safe loader; do not deserialize untrusted data with object-capable loaders.",
        re.compile(
            r"""(?ix)
            \b(?:pickle\.(?:load|loads)|_pickle\.(?:load|loads)|cPickle\.(?:load|loads))\b
            |\byaml\.load\s*\(
            |\bunserialize\s*\(
            |\breadObject\s*\(
            |\bXMLDecoder\s*\(
            |\bshelve\.open\s*\(
            |\bjsonpickle\.decode\s*\(
            |\bnode-serialize\.unserialize\s*\(
            |\bMarshal\.load\s*\(
            """
        ),
    ),
    (
        "CODE-DYNAMIC-EVAL",
        "high",
        0.80,
        "Dynamic code evaluation",
        "Dynamic evaluation can execute attacker-controlled input if the evaluated value is not fully trusted.",
        "Replace eval/exec with explicit parsing or a restricted mapping of supported operations.",
        re.compile(
            r"""(?ix)
            \b(?:eval|exec)\s*\(
            |new\s+Function\s*\(
            |vm\.(?:runInContext|runInNewContext|runInThisContext)\s*\(
            |compile\s*\([^)\n]*,\s*["'][^"']*["']\s*,\s*["'](?:exec|eval)["']
            |assert\s*\(\s*\$_(?:GET|POST|REQUEST)
            |preg_replace\s*\([^)\n]*\/e["']
            """
        ),
    ),
    (
        "TLS-VERIFY-DISABLED",
        "high",
        0.92,
        "TLS certificate verification disabled",
        "The client appears to skip TLS certificate validation, enabling interception of network traffic.",
        "Enable certificate verification and configure a trusted CA instead of disabling TLS checks.",
        re.compile(
            r"""(?ix)
            \bverify\s*=\s*False\b
            |\brejectUnauthorized\s*:\s*false\b
            |NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0
            |\bssl_verify\s*=\s*False\b
            |\bInsecureRequestWarning\b
            |CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)
            |CURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)
            |InsecureSkipVerify\s*:\s*true\b
            |TrustAllStrategy\b
            """
        ),
    ),
    (
        "HARDCODED-CREDENTIAL",
        "high",
        0.78,
        "Possible hardcoded credential",
        "A credential-like setting appears to be assigned a literal value in source code.",
        "Load credentials from a secret manager or environment configuration and rotate any exposed credential.",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|access[_-]?token|auth[_-]?token|jwt[_-]?secret)\b
            \s*[:=]\s*["'][^"'\s]{8,}["']
            """
        ),
    ),
    (
        "HARDCODED-API-TOKEN",
        "critical",
        0.95,
        "Exposed high-entropy API token or private key",
        "A well-known service token pattern (AWS key, GitHub token, Slack token, Stripe key, Google key, or Private Key) was detected.",
        "Immediately revoke and rotate the exposed token and purge it from source code history.",
        re.compile(
            r"""(?x)
            \bAKIA[0-9A-Z]{16}\b
            |\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b
            |\bxox[baprs]-[0-9a-zA-Z]{10,}\b
            |\b[rs]k_live_[0-9a-zA-Z]{24,}\b
            |\bAIza[0-9A-Za-z\-_]{30,40}\b
            |-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----
            """
        ),
    ),
    (
        "HARDCODED-DATABASE-URI",
        "high",
        0.90,
        "Hardcoded database connection string with credentials",
        "A database connection URI containing plaintext user credentials was detected in source code.",
        "Inject database connection strings via environment variables or IAM service account authentication.",
        re.compile(
            r"""(?ix)
            \b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s"']+@[a-zA-Z0-9_\-\.]+
            """
        ),
    ),
    (
        "WEB-UNSAFE-HTML",
        "medium",
        0.75,
        "Potential unsafe HTML insertion or DOM XSS",
        "HTML is inserted through a DOM API that does not escape content automatically.",
        "Escape or sanitize untrusted content, or use safe text APIs such as textContent.",
        re.compile(
            r"""(?ix)
            \.(?:innerHTML|outerHTML)\s*=
            |dangerouslySetInnerHTML\s*=
            |document\.(?:write|writeln)\s*\(
            |\.insertAdjacentHTML\s*\(
            |v-html\s*=
            |bypassSecurityTrustHtml\s*\(
            |bypassSecurityTrustScript\s*\(
            |mark_safe\s*\(
            |\{\%\s*autoescape\s+off\s*\%\}
            |echo\s+\$_(?:GET|POST|REQUEST)\[
            """
        ),
    ),
    (
        "SSRF-DYNAMIC-URL",
        "medium",
        0.72,
        "Possible server-side request forgery",
        "An outbound request may use a dynamically controlled URL. Untrusted destinations can expose internal services.",
        "Allowlist destinations and reject private, loopback, and link-local addresses after DNS resolution.",
        re.compile(
            r"""(?ix)
            (?:requests\.(?:get|post|put|delete|patch|head)|httpx\.(?:get|post|put|delete|patch)|fetch|axios\.(?:get|post))\s*\(\s*(?:request\.|req\.|user_url|target_url|dest_url|endpoint_url|webhook_url|remote_url|url\b)
            |urllib\.request\.urlopen\s*\(\s*(?:request\.|req\.|user_url|target|dest|endpoint|url\b)
            |curl_exec\s*\(\s*\$
            """
        ),
    ),
    (
        "PATH-TRAVERSAL",
        "high",
        0.85,
        "Potential path traversal or arbitrary file access",
        "File operations use unvalidated path components, potentially enabling directory traversal (../) to read or write sensitive files.",
        "Validate paths against an allowlist and resolve canonical paths to ensure they remain inside the intended directory.",
        re.compile(
            r"""(?ix)
            (?:open|send_file|send_from_directory|file_get_contents|readfile)\s*\(\s*(?:request\.|req\.|user_path|filename|filepath|f["'][^"']*(?:\{user|\{path|\{file))
            |fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:req\.|request\.|path\.join\([^)\n]*req\.)
            |(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)
            """
        ),
    ),
    (
        "TEMPLATE-INJECTION-SSTI",
        "high",
        0.86,
        "Server-side template injection (SSTI)",
        "Template strings are dynamically created with untrusted inputs rather than passing data as structured context variables.",
        "Never concatenate untrusted input into template strings. Use parameterized template context rendering.",
        re.compile(
            r"""(?ix)
            render_template_string\s*\(
            |jinja2\.Template\s*\([^)\n]*(?:request\.|req\.|f["']|["'][^"']*["']\s*\+)
            |mako\.template\.Template\s*\(
            |ejs\.render\s*\(\s*(?:req\.|request\.)
            |nunjucks\.renderString\s*\(\s*(?:req\.|request\.)
            |Handlebars\.compile\s*\(\s*(?:req\.|request\.)
            """
        ),
    ),
    (
        "WEAK-CRYPTOGRAPHY",
        "medium",
        0.85,
        "Use of broken or obsolete cryptographic algorithm",
        "The application employs weak cryptographic algorithms (MD5, SHA-1, DES, RC4, or ECB mode) susceptible to collision and cryptanalysis.",
        "Use SHA-256/SHA-3 for cryptographic hashing, Argon2id/bcrypt for passwords, and AES-GCM for encryption.",
        re.compile(
            r"""(?ix)
            hashlib\.(?:md5|sha1)\s*\(
            |crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']\)
            |Cipher\.getInstance\s*\(\s*["'](?:DES|RC4|Blowfish|AES/ECB)
            |AES\.MODE_ECB\b
            |DES\.new\s*\(
            |ARC4\.new\s*\(
            """
        ),
    ),
    (
        "INSECURE-RANDOM",
        "low",
        0.75,
        "Insecure pseudo-random number generator in security context",
        "Standard PRNGs (random, Math.random) are predictable and should not be used to generate security tokens, keys, or passwords.",
        "Use cryptographically secure random number generators (secrets module in Python, crypto.getRandomValues in JS).",
        re.compile(
            r"""(?ix)
            \b[a-zA-Z0-9_]*(?:token|secret|password|passwd|nonce|auth_code|salt)[a-zA-Z0-9_]*\b\s*[:=]\s*[^;\n]*(?:random\.(?:random|randint|choice)|Math\.random)\s*\(
            |["'][a-zA-Z0-9_]*(?:token|secret|password|nonce)[a-zA-Z0-9_]*["']\s*:\s*[^,\n]*(?:random\.(?:random|randint|choice)|Math\.random)\s*\(
            """
        ),
    ),
    (
        "INSECURE-JWT",
        "high",
        0.90,
        "Insecure JWT verification or 'none' algorithm accepted",
        "JWT verification is disabled or accepts the 'none' algorithm, allowing attackers to forge forged administrative tokens.",
        "Enforce signature verification and restrict allowed algorithms to secure asymmetric/symmetric schemes (RS256, HS256).",
        re.compile(
            r"""(?ix)
            jwt\.decode\s*\([^)\n]*(?:verify\s*=\s*False|verify_signature\s*[:=]\s*False)
            |algorithms\s*=\s*\[\s*["']none["']\s*\]
            |algorithm\s*=\s*["']none["']
            |options\s*=\s*\{[^}]*["']verify_signature["']\s*:\s*False
            """
        ),
    ),
    (
        "XML-EXTERNAL-ENTITY-XXE",
        "high",
        0.85,
        "XML External Entity (XXE) injection",
        "XML parser is configured to parse external entities or DTDs, enabling local file disclosure and SSRF attacks.",
        "Disable external entity resolution and DTD processing in all XML parsers.",
        re.compile(
            r"""(?ix)
            resolve_entities\s*=\s*True\b
            |etree\.XMLParser\s*\([^)\n]*resolve_entities\s*=\s*True
            |libxml_disable_entity_loader\s*\(\s*false\s*\)
            |setFeature\s*\(\s*["'][^"']*disallow-doctype-decl["']\s*,\s*false\s*\)
            """
        ),
    ),
    (
        "INSECURE-CORS",
        "medium",
        0.80,
        "Permissive CORS wildcard with credentials enabled",
        "Configuring CORS with allow_origins=['*'] alongside allow_credentials=True allows arbitrary websites to read authenticated user data.",
        "Specify explicit allowed origin domains rather than wildcard '*' when credentials are required.",
        re.compile(
            r"""(?ix)
            allow_origins\s*=\s*\[\s*["']\*["']\s*\]\s*,\s*allow_credentials\s*=\s*True
            |allow_credentials\s*=\s*True\s*,\s*allow_origins\s*=\s*\[\s*["']\*["']\s*\]
            |cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["'][^}]*credentials\s*:\s*true
            |res\.header\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\)
            """
        ),
    ),
    (
        "DEBUG-MODE-ENABLED",
        "medium",
        0.85,
        "Production debug mode enabled",
        "Application debug mode is enabled, which exposes interactive debugging consoles and detailed stack traces.",
        "Ensure debug flags are disabled in production and controlled exclusively via environment configuration.",
        re.compile(
            r"""(?ix)
            \bapp\.run\s*\([^)\n]*\bdebug\s*=\s*True
            |\bDEBUG\s*=\s*True\b
            |\bFLASK_DEBUG\s*=\s*["']?1["']?
            |NODE_ENV\s*=\s*["']development["']
            """
        ),
    ),
    (
        "OPEN-REDIRECT",
        "medium",
        0.75,
        "Potential unvalidated open redirect",
        "The application redirects users to a target specified directly in request parameters without domain validation.",
        "Validate redirect targets against an allowlist of relative URLs or trusted internal domains before issuing redirect.",
        re.compile(
            r"""(?ix)
            (?:redirect|res\.redirect)\s*\(\s*(?:request\.(?:args|values|GET|POST)|req\.(?:query|body))(?:\.(?:get\s*\(\s*|\[\s*)?["'](?:url|target|next|redirect|redirect_url|return|return_to|returnTo|dest|callback)["']|\.(?:url|target|next|redirect|redirect_url|returnTo|return_to|dest|callback)\b)
            |header\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)\[["'](?:url|target|next|redirect)
            """
        ),
    ),
    (
        "PROTOTYPE-POLLUTION",
        "high",
        0.82,
        "Potential JavaScript prototype pollution",
        "Merging or assigning untrusted input objects into object prototypes allows modification of Object.prototype.",
        "Validate keys against __proto__ and constructor, freeze prototypes, or use Map / Object.create(null).",
        re.compile(
            r"""(?ix)
            \b(?:__proto__|constructor\s*\[\s*["']prototype["']\])
            |Object\.assign\s*\([^,\n]*,\s*(?:req\.body|request\.body|JSON\.parse)
            |lodash\.merge\s*\([^,\n]*,\s*(?:req\.body|request\.body)
            """
        ),
    ),
    (
        "INSECURE-PERMISSIONS-OR-TEMP",
        "medium",
        0.80,
        "Insecure file permissions or unsafe temporary file creation",
        "World-writable permissions (0777) or deprecated mktemp allow local symlink attacks and unauthorized file tampering.",
        "Use tempfile.NamedTemporaryFile / mkstemp and restrict permissions to minimum necessary privileges (0600 / 0700).",
        re.compile(
            r"""(?ix)
            \btempfile\.mktemp\s*\(
            |\bos\.chmod\s*\([^,\n]*,\s*0o?777\)
            |\bchmodSync\s*\([^,\n]*,\s*0o?777\)
            """
        ),
    ),
    (
        "NOSQL-INJECTION",
        "high",
        0.80,
        "Potential NoSQL injection",
        "Unsanitized request body or query parameters are passed directly into NoSQL/MongoDB evaluation operators ($where, etc.).",
        "Sanitize inputs, avoid JavaScript execution in NoSQL queries, and enforce schema validation.",
        re.compile(
            r"""(?ix)
            \bfind(?:One)?\s*\(\s*\{[^}]*["']?\$where["']?\s*:
            |["']?\$where["']?\s*:\s*["'][^"']*\+
            |db\.[a-zA-Z_0-9]+\.(?:find|findOne|update|delete|deleteMany|updateOne)\s*\(\s*(?:req\.body|request\.json)
            """
        ),
    ),
    (
        "LDAP-INJECTION",
        "high",
        0.82,
        "Potential LDAP injection",
        "LDAP search filter queries are constructed with string formatting or concatenation with dynamic user input.",
        "Sanitize LDAP filter parameters with ldap.filter.escape_filter_chars() or use parameterized search helpers.",
        re.compile(
            r"""(?ix)
            ldap(?:\d)?\.(?:search|search_s|search_ext)\s*\([^)\n]*["'][^"']*=\s*["']\s*[\+\%]
            |ldap(?:\d)?\.(?:search|search_s|search_ext)\s*\([^)\n]*f["'][^"']*=[{]
            """
        ),
    ),
    (
        "REDOS-UNTRUSTED-REGEX",
        "medium",
        0.75,
        "Dynamic regular expression evaluation from untrusted input",
        "Constructing regular expressions from user input can cause catastrophic backtracking and denial of service (ReDoS).",
        "Avoid compiling dynamic regular expressions from untrusted input, or use non-backtracking engines like re2.",
        re.compile(
            r"""(?ix)
            new\s+RegExp\s*\(\s*(?:req\.|request\.|userInput|user_input|input)
            |re\.compile\s*\(\s*(?:request\.|req\.|user_input|userInput)
            """
        ),
    ),
    (
        "INSECURE-COOKIE",
        "low",
        0.75,
        "Insecure cookie configuration",
        "Cookie is set with HttpOnly or Secure flags disabled, exposing session tokens to script injection or network interception.",
        "Always set HttpOnly=True, Secure=True, and SameSite='Lax' or 'Strict' on sensitive cookies.",
        re.compile(
            r"""(?ix)
            set_cookie\s*\([^)\n]*\bhttponly\s*=\s*False
            |set_cookie\s*\([^)\n]*\bsecure\s*=\s*False
            |cookie\s*:\s*\{[^}]*secure\s*:\s*false
            |cookie\s*:\s*\{[^}]*httpOnly\s*:\s*false
            """
        ),
    ),
    (
        "CODE-BROKEN-AUTHENTICATION",
        "high",
        0.88,
        "Broken authentication check or bypass condition",
        "Authentication check functions contain hardcoded True return values or unconditional bypasses.",
        "Enforce cryptographic signature and password verification and eliminate hardcoded authentication bypass branches.",
        re.compile(
            r"""(?ix)
            def\s+is_authenticated\s*\([^)\n]*\)\s*:\s*return\s+True
            |def\s+check_password\s*\([^)\n]*\)\s*:\s*return\s+True
            |if\s+password\s*==\s*["'][^"']*["']\s*or\s+True\b
            """
        ),
    ),
    (
        "ZIP-SLIP-TRAVERSAL",
        "high",
        0.85,
        "Potential Zip Slip archive path traversal",
        "Archive extraction operations (tarfile/zipfile extractall) without member path validation can overwrite arbitrary system files.",
        "Inspect archive member paths, ensure they are relative, and verify with Path.resolve() that they stay within the target directory.",
        re.compile(r"""(?ix)\b(?:tarfile|zipfile|tar|zip_ref|zipArchive|archive)\.(?:extractall|extract)\s*\("""),
    ),
    (
        "TIMING-ATTACK-EQUALITY",
        "medium",
        0.78,
        "Potential timing attack on cryptographic secret",
        "Comparing cryptographic hashes, signatures, tokens, or MACs using standard equality operators leaks timing information.",
        "Use constant-time comparison functions such as hmac.compare_digest() in Python or crypto.timingSafeEqual() in Node.js.",
        re.compile(
            r"""(?ix)
            (?:signature|hmac|hash|digest|auth_tag|mac)\s*(?:===?|!==?)\s*[a-zA-Z0-9_]
            |[a-zA-Z0-9_]+\s*(?:===?|!==?)\s*(?:signature|hmac|hash|digest|auth_tag|mac)\b
            """
        ),
    ),
    (
        "MASS-ASSIGNMENT",
        "high",
        0.80,
        "Potential mass assignment or parameter tampering",
        "Binding raw client request parameters directly to database model creation or update methods allows unauthorized parameter tampering.",
        "Use an explicit allowlist of permitted fields (e.g., Pydantic schema validation or explicit field mapping) before persisting.",
        re.compile(
            r"""(?ix)
            \b(?:objects\.create|create|update|update_attributes)\s*\(\s*\*\*(?:request\.(?:POST|GET|json|data)|req\.body)
            |\bparams\.permit!\b
            |\b[A-Z][a-zA-Z0-9_]*\.(?:create|update)\s*\(\s*(?:req\.body|request\.json)\s*\)
            """
        ),
    ),
    (
        "SENSITIVE-DATA-LOGGING",
        "medium",
        0.76,
        "Sensitive data exposure in application logs",
        "Writing credentials, passwords, auth tokens, or API secrets into logs exposes them to centralized log monitoring tools.",
        "Sanitize log outputs, redact sensitive keys, or use structured log filtering.",
        re.compile(
            r"""(?ix)
            (?:logging\.(?:debug|info|warning|error)|logger\.(?:debug|info|warning|error)|console\.(?:log|error|warn))\s*\([^)\n]*(?:password|passwd|api[_-]?key|client[_-]?secret|access[_-]?token|bearer[_-]?token|auth[_-]?header)
            """
        ),
    ),
    (
        "DANGEROUS-FILE-UPLOAD",
        "high",
        0.82,
        "Insecure file upload path construction",
        "Saving uploaded files directly with user-supplied filenames can allow path traversal or executable script uploads.",
        "Sanitize uploaded filenames with werkzeug.utils.secure_filename(), generate randomized storage keys (UUIDs), and validate MIME types.",
        re.compile(
            r"""(?ix)
            \bfile\.save\s*\([^)\n]*file\.filename
            |\breq\.files\.[a-zA-Z0-9_]+\.mv\s*\(
            |\b(?:upload|uploads)\s*\.\s*save\s*\([^)\n]*filename
            """
        ),
    ),
    (
        "CSRF-PROTECTION-DISABLED",
        "medium",
        0.84,
        "Cross-Site Request Forgery (CSRF) protection disabled",
        "Disabling CSRF middleware on state-changing endpoints allows third-party websites to forge requests on behalf of authenticated users.",
        "Keep CSRF validation enabled on all browser-facing state-changing endpoints, using Anti-CSRF tokens or SameSite cookie policies.",
        re.compile(
            r"""(?ix)
            @(?:csrf_exempt|csrf\.exempt)\b
            |csrf\s*:\s*false\b
            |WTF_CSRF_ENABLED\s*=\s*False\b
            """
        ),
    ),
    (
        "GRAPHQL-UNBOUNDED-OR-INTROSPECTION",
        "low",
        0.75,
        "GraphQL schema introspection or unbounded query depth",
        "Enabling schema introspection in production leaks backend APIs, while missing query depth limits enables resource exhaustion.",
        "Disable GraphQL introspection in production and enforce query depth/complexity limits with validation rules.",
        re.compile(
            r"""(?ix)
            \bintrospection\s*[:=]\s*True\b
            |\bintrospection\s*:\s*true\b
            |\bvalidation_rules\s*=\s*\[\s*\]
            """
        ),
    ),
    (
        "STATIC-CRYPTO-IV-OR-SALT",
        "medium",
        0.82,
        "Static or hardcoded cryptographic IV or salt",
        "Reusing static initialization vectors (IVs) or fixed salts undermines cipher security and allows dictionary attacks against hashes.",
        "Generate unique, cryptographically random IVs (os.urandom(16)) and random salts for every encryption and hashing operation.",
        re.compile(
            r"""(?ix)
            \b(?:iv|initialization_vector)\s*=\s*(?:b["']0{8,}["']|b["']\\x00{8,}["']|["']0{8,}["'])
            |\bsalt\s*=\s*b?["'][a-zA-Z0-9_\-]{1,16}["']\b
            """
        ),
    ),
    (
        "UNSAFE-C-MEM-FUNCTION",
        "high",
        0.86,
        "Unsafe C/C++ memory operation (Buffer Overflow risk)",
        "Legacy C memory and string manipulation functions without explicit length bounds are susceptible to buffer overflows.",
        "Replace legacy functions with bounded alternatives: use strncpy_s / snprintf / fgets instead of strcpy, gets, and sprintf.",
        re.compile(
            r"""(?ix)
            \b(?:strcpy|strcat|sprintf|vsprintf)\s*\([^)\n]*,
            |\bgets\s*\(
            |\bscanf\s*\(\s*["']%s["']
            """
        ),
    ),
    (
        "SENSITIVE-EXCEPTION-LEAK",
        "medium",
        0.75,
        "Raw exception details or stack trace exposed in response",
        "Returning raw exception objects or stack traces directly in API responses leaks system architecture and file paths.",
        "Log detailed exceptions internally and return generic, user-friendly error codes or messages to clients.",
        re.compile(
            r"""(?ix)
            res\.status\s*\(\s*500\s*\)\.send\s*\(\s*err(?:\.stack)?\s*\)
            |res\.(?:json|send)\s*\(\s*\{\s*error\s*:\s*err(?:\.message|\.stack)?\s*\}
            |return\s+(?:jsonify\s*\(\s*)?\{[^}]*["']error["']\s*:\s*str\s*\(\s*e\s*\)
            """
        ),
    ),
)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").lstrip("/").casefold()


def is_security_scan_candidate(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if normalized.startswith("/") or any(part in (".", "..") for part in parts):
        return False
    if any(part.casefold() in IGNORED_DIRECTORIES for part in parts):
        return False
    if PurePosixPath(normalized).suffix.casefold() not in SOURCE_EXTENSIONS:
        return False
    filename = PurePosixPath(normalized).name.casefold()
    if filename in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "gemfile.lock"):
        return False
    return not (filename.endswith(".min.js") or filename.endswith(".min.css") or filename.endswith(".map"))


def scan_security_files(
    files: List[Dict[str, Any]],
    changed_paths: Optional[Set[str]] = None
) -> List[SecurityFinding]:
    """Apply local, heuristic security checks without retaining source snippets."""
    changed_paths = changed_paths or set()
    findings: List[SecurityFinding] = []

    for file_info in files:
        path = str(file_info.get("filename", ""))
        content = file_info.get("content", "")
        if not path or not isinstance(content, str):
            continue

        per_file_count = 0
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule_id, severity, confidence, title, description, recommendation, pattern in RULES:
                if not pattern.search(line):
                    continue
                if (
                    rule_id == "CODE-UNSAFE-DESERIALIZATION"
                    and "yaml.load" in line.lower()
                    and ("safeloader" in line.lower() or "safe_load" in line.lower())
                ):
                    continue
                findings.append(SecurityFinding(
                    id=f"security-{len(findings) + 1:04d}",
                    rule_id=rule_id,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    file=path,
                    line=line_number,
                    changed_in_deployment=_normalize_path(path) in changed_paths
                ))
                per_file_count += 1
                if per_file_count >= MAX_FINDINGS_PER_FILE:
                    break
            if per_file_count >= MAX_FINDINGS_PER_FILE:
                break

    return findings


async def scan_github_repository(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    changed_files: List[Dict[str, Any]]
) -> SecurityScanReport:
    """Fetch and scan a bounded source snapshot from a GitHub repository."""
    try:
        tree, tree_truncated = await client.get_repository_tree(owner, repo, ref)
    except GitHubAPIError:
        return SecurityScanReport(
            status="unavailable",
            message="GitHub did not provide the repository tree. Check repository visibility and token permissions."
        )
    except httpx.HTTPError:
        return SecurityScanReport(
            status="unavailable",
            message="GitHub could not be reached to retrieve the repository tree."
        )

    candidate_paths = [
        item["path"]
        for item in tree
        if item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and is_security_scan_candidate(item["path"])
    ]
    changed_paths = {
        _normalize_path(str(file_info.get("filename", "")))
        for file_info in changed_files
        if file_info.get("filename")
    }

    # Prioritize deployment changed paths first, then stable repository files
    prioritized_paths = sorted(
        candidate_paths,
        key=lambda p: (0 if _normalize_path(p) in changed_paths else 1, p)
    )
    paths_to_scan = prioritized_paths[:MAX_SECURITY_SCAN_FILES]

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_FILE_REQUESTS)
    failed_files = 0

    async def fetch_file(path: str) -> Optional[Dict[str, str]]:
        nonlocal failed_files
        async with semaphore:
            try:
                content = await client.get_file_content(
                    owner,
                    repo,
                    path,
                    ref=ref,
                    max_bytes=MAX_SECURITY_FILE_BYTES
                )
            except (GitHubAPIError, httpx.HTTPError):
                failed_files += 1
                return None
        if content is None:
            failed_files += 1
            return None
        return {"filename": path, "content": content}

    fetched = await asyncio.gather(*(fetch_file(path) for path in paths_to_scan))
    source_files = [file_info for file_info in fetched if file_info is not None]
    findings = scan_security_files(source_files, changed_paths)

    incomplete = (
        tree_truncated
        or len(candidate_paths) > MAX_SECURITY_SCAN_FILES
        or failed_files > 0
    )
    status = "partial" if incomplete else "completed"
    details = [
        f"Scanned {len(source_files)} of {len(candidate_paths)} candidate source files."
    ]
    if failed_files:
        details.append(f"{failed_files} file(s) could not be read.")
    if len(candidate_paths) > MAX_SECURITY_SCAN_FILES:
        details.append(f"Scan capped at {MAX_SECURITY_SCAN_FILES} files.")
    if tree_truncated:
        details.append("GitHub truncated the repository file listing.")
    details.append(
        "Findings are heuristic signals, not proof of exploitability; "
        "a file changed by this deployment is not necessarily a newly introduced issue."
    )

    report = SecurityScanReport(
        status=status,
        message=" ".join(details),
        candidates_total=len(candidate_paths),
        files_scanned=len(source_files),
        findings=findings
    )
    if findings:
        report.ai_triage = await GroqAnalyzer().triage_security_findings(findings)
    else:
        report.ai_triage = SecurityAITriage(
            status="not_run",
            message="No pattern matches were found; AI triage was not requested."
        )
    return report
