import asyncio
import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

OWASP_CATEGORIES = {
    "API1":  "Broken Object Level Authorization",
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API4":  "Unrestricted Resource Consumption",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Unrestricted Access to Sensitive Business Flows",
    "API7":  "Server Side Request Forgery",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of Third-Party APIs",
}

SENSITIVE_DATA_PATTERNS = [
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),                                                    "credit_card"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                                                        "ssn"),
    (re.compile(r'[:=]\s*["\'](A3T[A-Z0-9]{16,})["\']',                                              re.I),     "aws_access_key"),
    (re.compile(r'[:=]\s*["\'](xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})["\']',     re.I),     "slack_token"),
    (re.compile(r'[:=]\s*["\'](eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)["\']\b'),            "jwt_exposed"),
    (re.compile(r'["\'](?:password|secret|api_?key|private_?key)["\']\s*:\s*["\']([^"\'*]{8,})["\']', re.I),   "hardcoded_secret_value"),
]

DEBUG_PATHS = [
    re.compile(r'/(?:debug|actuator|vars|env|heapdump|trace|phpinfo|server-status)(?:/|$)', re.I),
    re.compile(r'/\.env$', re.I),
]

MISSING_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
]

INTERNAL_FIELDS       = {
    "is_admin", "is_superuser", "role_id", "internal_id",
    "privileges", "permissions_mask", "account_status",
}

SENSITIVE_KEYWORDS    = {
    "user", "account", "profile", "admin", "payment",
    "order", "invoice", "settings", "config", "vault",
}

SENSITIVE_FLOW_KEYWORDS = {
    "payment", "transfer", "withdraw", "checkout",
    "purchase", "refund", "transaction", "payout",
    "topup", "deposit", "wallet", "billing",
}

SSRF_PARAM_KEYWORDS   = {
    "url", "uri", "redirect", "callback", "webhook",
    "dest", "destination", "return", "next", "target",
    "endpoint", "proxy", "forward", "fetch", "load",
}

RATE_LIMIT_HEADERS    = {
    "x-ratelimit-limit", "x-rate-limit-limit",
    "x-ratelimit-remaining", "ratelimit-limit",
    "retry-after",
}

BULK_PATH_PATTERN     = re.compile(r'/(?:bulk|batch|import|export|all|list)(?:/|$)', re.I)
PARAM_PATH_PATTERN    = re.compile(r'/(?:\{[^}]+\}|:\w+|<[^>]+>|\d{2,})(?:/|$)')
ADMIN_PATH_PATTERN    = re.compile(
    r'/(?:admin|administration|management|manage|backoffice|superuser|root|internal|privileged)(?:/|$)', re.I
)


class OWASPScanner:
    def __init__(self, store, cfg: dict):
        self.store        = store
        self.cfg          = cfg
        self.owasp_cfg    = cfg.get("owasp", {})
        self._checked_hosts: Set[str] = set()

    async def run(self):
        entries = self.store.all()
        active_entries = [
            e for e in entries
            if getattr(e, "status_code", 0) and e.status_code not in (404, 410)
            and not e.endpoint.startswith("source_finding")
        ]

        if not active_entries:
            print("    No active endpoints to assess")
            return

        print(f"    OWASP passive assessment: {len(active_entries)} endpoints")

        for entry in active_entries:
            await self._assess_entry(entry)

        self._check_api10_global()

        flagged = sum(1 for e in entries if getattr(e, "owasp_flags", []))
        print(f"    OWASP: {flagged} endpoints with findings")

    async def _assess_entry(self, entry):
        flags = []

        if self.owasp_cfg.get("test_bola", True):
            flags += self._check_api1_passive(entry)

        if self.owasp_cfg.get("test_broken_auth", True):
            flags += self._check_api2_passive(entry)

        if self.owasp_cfg.get("test_mass_assignment", True):
            flags += self._check_api3_passive(entry)

        if self.owasp_cfg.get("test_rate_limit", True):
            flags += self._check_api4_passive(entry)

        if self.owasp_cfg.get("test_bfla", True):
            flags += self._check_api5_passive(entry)

        if self.owasp_cfg.get("test_sensitive_flows", True):
            flags += self._check_api6_passive(entry)

        if self.owasp_cfg.get("test_ssrf", True):
            flags += self._check_api7_passive(entry)

        if self.owasp_cfg.get("test_misconfiguration", True):
            flags += self._check_api8_passive(entry)

        if self.owasp_cfg.get("test_inventory", True):
            flags += self._check_api9_passive(entry)

        if flags:
            if not hasattr(entry, "owasp_flags") or entry.owasp_flags is None:
                entry.owasp_flags = []
            entry.owasp_flags.extend(flags)

    def _headers(self, entry) -> Dict[str, str]:
        return {k.lower(): str(v) for k, v in (getattr(entry, "headers_observed", {}) or {}).items()}

    def _has_auth(self, headers: Dict[str, str]) -> bool:
        return any(h in headers for h in ["authorization", "x-api-key", "api-key", "cookie", "token"])

    def _check_api1_passive(self, entry) -> List[Dict]:
        flags   = []
        headers = self._headers(entry)

        if not PARAM_PATH_PATTERN.search(entry.endpoint):
            return flags

        if self._has_auth(headers):
            return flags

        if entry.status_code == 200:
            flags.append({
                "category": "API1",
                "name":     OWASP_CATEGORIES["API1"],
                "finding":  "Parameterized endpoint returned 200 with no authentication headers observed. "
                            "Manual BOLA testing required to confirm object-level access control.",
                "severity": "HIGH",
                "endpoint": entry.endpoint,
            })
        return flags

    def _check_api2_passive(self, entry) -> List[Dict]:
        flags    = []
        headers  = self._headers(entry)
        path_lower = urlparse(entry.endpoint).path.lower()

        if entry.status_code == 200 and not self._has_auth(headers):
            path_segments = set(re.split(r'[/_\-]', path_lower))
            if path_segments.intersection(SENSITIVE_KEYWORDS):
                flags.append({
                    "category": "API2",
                    "name":     OWASP_CATEGORIES["API2"],
                    "finding":  "Sensitive endpoint accessible without detected authentication headers",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                })
        return flags

    def _check_api3_passive(self, entry) -> List[Dict]:
        flags        = []
        resp_preview = str(getattr(entry, "evidence", {}).get("response_preview", "")).lower()
        if not resp_preview:
            return flags

        found_fields = [
            f for f in INTERNAL_FIELDS
            if f'"{f}"' in resp_preview or f"'{f}'" in resp_preview
        ]
        if found_fields:
            flags.append({
                "category": "API3",
                "name":     OWASP_CATEGORIES["API3"],
                "finding":  f"Administrative or internal fields reflected in response body: {', '.join(found_fields)}. "
                            f"Verify these are not writable by unprivileged clients.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })
        return flags

    def _check_api4_passive(self, entry) -> List[Dict]:
        flags   = []
        headers = self._headers(entry)

        is_upload = any(kw in entry.endpoint.lower() for kw in ["/upload", "/import", "/ingest", "/file"])
        is_bulk   = bool(BULK_PATH_PATTERN.search(entry.endpoint))
        method    = getattr(entry, "method", "UNKNOWN").upper()

        has_rate_limit = bool(RATE_LIMIT_HEADERS.intersection(headers.keys()))

        if (is_upload or is_bulk) and method in ("POST", "PUT", "PATCH") and not has_rate_limit:
            label = "File upload" if is_upload else "Bulk operation"
            flags.append({
                "category": "API4",
                "name":     OWASP_CATEGORIES["API4"],
                "finding":  f"{label} endpoint with no rate-limiting headers detected. "
                            f"Verify server-side file size limits, rate limits, and resource quotas are enforced.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })
        elif entry.status_code == 200 and not has_rate_limit and method == "GET":
            if any(kw in entry.endpoint.lower() for kw in ["/all", "/list", "/export", "/dump"]):
                flags.append({
                    "category": "API4",
                    "name":     OWASP_CATEGORIES["API4"],
                    "finding":  "Unbounded data retrieval endpoint with no rate-limiting headers. "
                                "Large result sets without pagination or throttling risk resource exhaustion.",
                    "severity": "LOW",
                    "endpoint": entry.endpoint,
                })
        return flags

    def _check_api5_passive(self, entry) -> List[Dict]:
        flags   = []
        headers = self._headers(entry)

        if not ADMIN_PATH_PATTERN.search(entry.endpoint):
            return flags

        if entry.status_code == 200 and not self._has_auth(headers):
            flags.append({
                "category": "API5",
                "name":     OWASP_CATEGORIES["API5"],
                "finding":  "Administrative or privileged endpoint returned 200 with no authentication headers. "
                            "Verify function-level access control is enforced server-side.",
                "severity": "CRITICAL",
                "endpoint": entry.endpoint,
            })
        return flags

    def _check_api6_passive(self, entry) -> List[Dict]:
        flags      = []
        headers    = self._headers(entry)
        path_lower = urlparse(entry.endpoint).path.lower()
        segments   = set(re.split(r'[/_\-]', path_lower))

        if not segments.intersection(SENSITIVE_FLOW_KEYWORDS):
            return flags

        has_rate_limit = bool(RATE_LIMIT_HEADERS.intersection(headers.keys()))

        if entry.status_code == 200 and not self._has_auth(headers):
            flags.append({
                "category": "API6",
                "name":     OWASP_CATEGORIES["API6"],
                "finding":  "Sensitive business flow endpoint (payment/transfer/checkout) accessible without "
                            "detected authentication. Verify access controls and business logic enforcement.",
                "severity": "CRITICAL",
                "endpoint": entry.endpoint,
            })
        elif entry.status_code == 200 and not has_rate_limit:
            flags.append({
                "category": "API6",
                "name":     OWASP_CATEGORIES["API6"],
                "finding":  "Sensitive business flow endpoint has no rate-limiting headers. "
                            "Abuse of payment or transfer flows without throttling is a critical risk.",
                "severity": "HIGH",
                "endpoint": entry.endpoint,
            })
        return flags

    def _check_api7_passive(self, entry) -> List[Dict]:
        flags  = []
        parsed = urlparse(entry.endpoint)
        params = parse_qs(parsed.query)

        ssrf_params = [k for k in params if k.lower() in SSRF_PARAM_KEYWORDS]
        if not ssrf_params:
            return flags

        flags.append({
            "category":  "API7",
            "name":      OWASP_CATEGORIES["API7"],
            "finding":   f"Endpoint accepts URL-like parameter(s): {', '.join(ssrf_params)}. "
                         f"These are commonly exploited for SSRF. Manual testing against internal metadata "
                         f"endpoints (169.254.169.254, localhost) is strongly recommended.",
            "severity":  "HIGH",
            "endpoint":  entry.endpoint,
        })
        return flags

    def _check_api8_passive(self, entry) -> List[Dict]:
        flags    = []
        endpoint = entry.endpoint
        parsed   = urlparse(endpoint)
        host     = parsed.netloc
        headers  = self._headers(entry)

        if host and host not in self._checked_hosts:
            for h in MISSING_SECURITY_HEADERS:
                if h not in headers:
                    flags.append({
                        "category": "API8",
                        "name":     OWASP_CATEGORIES["API8"],
                        "finding":  f"Missing security header '{h}' on host — applies to all endpoints on this host",
                        "severity": "LOW",
                        "endpoint": f"{parsed.scheme}://{host}/*",
                    })
            self._checked_hosts.add(host)

        cors = headers.get("access-control-allow-origin", "")
        if cors in ("*", "null"):
            flags.append({
                "category": "API8",
                "name":     OWASP_CATEGORIES["API8"],
                "finding":  f"Permissive CORS policy: Access-Control-Allow-Origin: {cors}",
                "severity": "MEDIUM",
                "endpoint": endpoint,
            })

        for pat in DEBUG_PATHS:
            if pat.search(parsed.path):
                flags.append({
                    "category": "API8",
                    "name":     OWASP_CATEGORIES["API8"],
                    "finding":  "Debug or diagnostic endpoint exposed",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                })

        resp_preview = str(getattr(entry, "evidence", {}).get("response_preview", ""))
        if resp_preview:
            for pat, label in SENSITIVE_DATA_PATTERNS:
                match = pat.search(resp_preview)
                if match:
                    val = match.group(1) if match.groups() else match.group(0)
                    if len(set(val)) < 4:
                        continue
                    flags.append({
                        "category": "API8",
                        "name":     OWASP_CATEGORIES["API8"],
                        "finding":  f"Sensitive data exposure in response: {label}",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                    })
        return flags

    def _check_api9_passive(self, entry) -> List[Dict]:
        flags = []
        path  = urlparse(entry.endpoint).path

        if getattr(entry, "classification", "") == "Shadow":
            flags.append({
                "category": "API9",
                "name":     OWASP_CATEGORIES["API9"],
                "finding":  "Shadow API: endpoint exists in codebase or traffic but is absent from any "
                            "API registry, gateway, or OpenAPI specification",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })

        version_match = re.search(r'/v(\d+)/', path)
        if version_match:
            current_v   = int(version_match.group(1))
            next_v_path = path.replace(f"/v{current_v}/", f"/v{current_v + 1}/")
            if hasattr(self.store, "seen_endpoint") and self.store.seen_endpoint(next_v_path):
                flags.append({
                    "category": "API9",
                    "name":     OWASP_CATEGORIES["API9"],
                    "finding":  f"Deprecated API version v{current_v} is still active alongside a newer version. "
                                f"Decommission or redirect legacy versions.",
                    "severity": "LOW",
                    "endpoint": entry.endpoint,
                })
        return flags

    def _check_api10_global(self):
        inventory = getattr(self.store, "outbound_api_inventory", [])
        if not inventory:
            return

        global_flags = []
        for item in inventory:
            url = item.get("url", "")
            if url.startswith("http://"):
                global_flags.append({
                    "category": "API10",
                    "name":     OWASP_CATEGORIES["API10"],
                    "finding":  f"Outbound call to {item.get('host')} uses unencrypted HTTP. "
                                f"All third-party API communication must use HTTPS.",
                    "severity": "HIGH",
                    "endpoint": "Outbound Integration",
                    "url":      url,
                })

        if global_flags:
            dummy_entry = self.store.get_or_create_finding_placeholder("Global Third-Party Risks")
            if not hasattr(dummy_entry, "owasp_flags") or dummy_entry.owasp_flags is None:
                dummy_entry.owasp_flags = []
            dummy_entry.owasp_flags.extend(global_flags)