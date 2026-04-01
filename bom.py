import argparse
import json
import os
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bom_ref(value: str) -> str:
    return "bom-ref-" + hashlib.md5(value.encode()).hexdigest()[:12]


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _severity_to_cvss_rating(cvss: Optional[float]) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _auth_to_cdx_auth(auth_type: Optional[str]) -> bool:
    if not auth_type:
        return False
    no_auth = {"none detected", "unknown", "no auth required", ""}
    return auth_type.lower() not in no_auth


def _sensitivity_to_cdx_flow(sensitivity: str, endpoint_url: str) -> Optional[dict]:
    classification_map = {
        "CRITICAL": "credential",
        "HIGH":     "pii",
        "MEDIUM":   "phi",
        "LOW":      "non-sensitive",
    }
    cls = classification_map.get((sensitivity or "").upper())
    if not cls:
        return None
    return {
        "flow":            "bi-directional",
        "classification":  cls,
    }


def _parse_endpoint_url(url: str) -> dict:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return {
            "scheme":   parsed.scheme or "http",
            "host":     parsed.netloc or url,
            "path":     parsed.path or "/",
            "query":    parsed.query or None,
        }
    except Exception:
        return {"scheme": "http", "host": url, "path": "/", "query": None}


def generate_cyclonedx(full: dict, engagement_meta: dict) -> dict:
    summary      = full.get("summary", {})
    bom_data     = full.get("api_bom", {})
    tech_stack   = bom_data.get("tech_stack", {})
    all_endpoints = full.get("all_endpoints", [])
    cve_summary  = full.get("cve_findings_summary", [])
    pkg_deps     = bom_data.get("package_dependencies", [])
    outbound_apis = full.get(
        "inbound_outbound_classification", {}
    ).get("outbound_apis", {}).get("apis", [])

    serial_number = f"urn:uuid:{uuid.uuid4()}"
    bom_ref_main  = _bom_ref(engagement_meta.get("app_name", "api-discovery-platform"))

    components: List[dict] = []
    services:   List[dict] = []
    vulnerabilities: List[dict] = []
    dependencies: List[dict] = []
    service_refs: List[str] = []

    for pkg in pkg_deps:
        name    = pkg.get("name") or "unknown"
        version = pkg.get("version") or "unknown"
        eco     = pkg.get("ecosystem") or "generic"

        purl_map = {
            "npm":    f"pkg:npm/{name}@{version}",
            "pypi":   f"pkg:pypi/{name}@{version}",
            "maven":  f"pkg:maven/{name}@{version}",
            "nuget":  f"pkg:nuget/{name}@{version}",
            "gradle": f"pkg:maven/{name}@{version}",
        }
        purl    = purl_map.get(eco, f"pkg:generic/{name}@{version}")
        ref     = _bom_ref(f"pkg-{name}-{version}")

        components.append({
            "type":            "library",
            "bom-ref":         ref,
            "name":            name,
            "version":         version,
            "purl":            purl,
            "properties": [
                {"name": "cdx:ecosystem", "value": eco},
            ],
        })
        dependencies.append({"ref": ref, "dependsOn": []})

    endpoint_url_to_ref: Dict[str, str] = {}

    for ep in all_endpoints:
        url        = ep.get("endpoint") or ep.get("url") or ""
        method     = ep.get("method") or "UNKNOWN"
        auth_type  = ep.get("auth_type") or ""
        sensitivity = ep.get("data_sensitivity") or "UNKNOWN"
        cls        = ep.get("classification") or "UNCLASSIFIED"
        module     = ep.get("functional_module") or "Uncategorized"
        owner      = ep.get("inferred_owner") or ""
        risk_score = ep.get("risk_score", 0)
        risk_band  = ep.get("risk_band") or "LOW"

        ref = _bom_ref(f"svc-{url}-{method}")
        endpoint_url_to_ref[url] = ref
        service_refs.append(ref)

        parsed = _parse_endpoint_url(url)
        svc_ep = f"{parsed['scheme']}://{parsed['host']}{parsed['path']}"

        data_flows = []
        flow = _sensitivity_to_cdx_flow(sensitivity, url)
        if flow:
            data_flows.append(flow)

        svc: dict = {
            "bom-ref":         ref,
            "name":            f"{method} {parsed['path']}",
            "description":     f"{module} — {cls} API endpoint",
            "endpoints":       [svc_ep],
            "authenticated":   _auth_to_cdx_auth(auth_type),
            "x-trust-boundary": cls in ("Rogue", "Shadow"),
            "properties": [
                {"name": "api:method",           "value": method},
                {"name": "api:classification",   "value": cls},
                {"name": "api:data_sensitivity", "value": sensitivity},
                {"name": "api:auth_type",        "value": auth_type or "None detected"},
                {"name": "api:risk_score",       "value": str(risk_score)},
                {"name": "api:risk_band",        "value": risk_band},
                {"name": "api:functional_module","value": module},
                {"name": "api:owner",            "value": owner},
            ],
        }

        if data_flows:
            svc["data"] = data_flows

        owasp_cats = [f.get("category") for f in ep.get("owasp_flags", []) if f.get("category")]
        if owasp_cats:
            svc["properties"].append({
                "name":  "api:owasp_findings",
                "value": ", ".join(sorted(set(owasp_cats))),
            })

        services.append(svc)

        cve_findings = ep.get("cve_findings", [])
        for cve in cve_findings:
            cve_id = cve.get("cve") or cve.get("CVENumber")
            if not cve_id:
                continue
            cvss_score = cve.get("cvss")
            vuln: dict = {
                "bom-ref":     _bom_ref(f"vuln-{cve_id}-{ref}"),
                "id":          cve_id,
                "source":      {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                "description": cve.get("desc") or cve.get("description") or "",
                "ratings": [
                    {
                        "source":   {"name": "NVD"},
                        "score":    cvss_score,
                        "severity": _severity_to_cvss_rating(cvss_score),
                        "method":   "CVSSv3",
                    }
                ] if cvss_score else [],
                "affects": [
                    {
                        "ref": ref,
                        "versions": [{"version": cve.get("installed_version", "unknown")}],
                    }
                ],
            }
            vulnerabilities.append(vuln)

    outbound_service_refs: List[str] = []
    for api in outbound_apis:
        url         = api.get("url") or api.get("host") or ""
        integration = api.get("integration") or url
        category    = api.get("category") or "external"
        exposure    = api.get("exposure") or "External"
        auth_method = api.get("auth_method") or "unknown"
        risk        = api.get("risk") or "MEDIUM"

        ref = _bom_ref(f"outbound-{url}")
        outbound_service_refs.append(ref)

        services.append({
            "bom-ref":     ref,
            "name":        integration,
            "description": f"Outbound dependency — {category}",
            "endpoints":   [url] if url.startswith("http") else [],
            "authenticated": auth_method not in ("none", "unknown"),
            "x-trust-boundary": exposure == "External",
            "properties": [
                {"name": "api:direction",   "value": "outbound"},
                {"name": "api:category",    "value": category},
                {"name": "api:exposure",    "value": exposure},
                {"name": "api:auth_method", "value": auth_method},
                {"name": "api:risk",        "value": risk},
            ],
        })

    for cve in cve_summary:
        cve_id = cve.get("cve") or cve.get("CVENumber")
        if not cve_id:
            continue
        already = any(v["id"] == cve_id for v in vulnerabilities)
        if already:
            continue
        cvss_score = cve.get("cvss")
        vulnerabilities.append({
            "bom-ref":     _bom_ref(f"vuln-global-{cve_id}"),
            "id":          cve_id,
            "source":      {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            "description": cve.get("desc") or cve.get("description") or "",
            "ratings": [
                {
                    "source":   {"name": "NVD"},
                    "score":    cvss_score,
                    "severity": _severity_to_cvss_rating(cvss_score),
                    "method":   "CVSSv3",
                }
            ] if cvss_score else [],
            "affects": [{"ref": bom_ref_main}],
        })

    main_service: dict = {
        "bom-ref":     bom_ref_main,
        "name":        engagement_meta.get("app_name", "Target Application"),
        "description": f"API BOM for {engagement_meta.get('client_name', 'Client')} — "
                       f"{engagement_meta.get('engagement', 'API Discovery & Security Evaluation')}",
        "version":     "1.0",
        "properties": [
            {"name": "scan:total_endpoints",    "value": str(summary.get("total", 0))},
            {"name": "scan:shadow_count",       "value": str(summary.get("Shadow", 0))},
            {"name": "scan:rogue_count",        "value": str(summary.get("Rogue", 0))},
            {"name": "scan:valid_count",        "value": str(summary.get("Valid", 0))},
            {"name": "scan:secrets_count",      "value": str(summary.get("secrets_count", 0))},
            {"name": "scan:owasp_total",        "value": str(summary.get("owasp_findings_total", 0))},
            {"name": "scan:cve_total",          "value": str(summary.get("cve_findings_total", 0))},
            {"name": "tech:runtime",            "value": tech_stack.get("runtime", "unknown")},
            {"name": "tech:framework",          "value": tech_stack.get("framework", "unknown")},
            {"name": "tech:language",           "value": tech_stack.get("language", "unknown")},
        ],
    }

    if service_refs:
        main_service["services"] = service_refs

    dependencies.append({
        "ref":       bom_ref_main,
        "dependsOn": outbound_service_refs,
    })

    bom = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version":     1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [
                {
                    "vendor":  "API Discovery Platform",
                    "name":    "api-discovery-platform",
                    "version": "2.0.0",
                }
            ],
            "component": {
                "type":    "application",
                "bom-ref": bom_ref_main,
                "name":    engagement_meta.get("app_name", "Target Application"),
            },
            "properties": [
                {"name": "engagement",  "value": engagement_meta.get("engagement", "")},
                {"name": "client",      "value": engagement_meta.get("client_name", "")},
                {"name": "generated_at","value": full.get("generated_at", _now_iso())},
            ],
        },
        "components":      components,
        "services":        [main_service] + services,
        "vulnerabilities": vulnerabilities,
        "dependencies":    dependencies,
    }

    return bom


def generate_spdx(full: dict, engagement_meta: dict) -> dict:
    bom_data      = full.get("api_bom", {})
    tech_stack    = bom_data.get("tech_stack", {})
    all_endpoints = full.get("all_endpoints", [])
    pkg_deps      = bom_data.get("package_dependencies", [])
    cve_summary   = full.get("cve_findings_summary", [])
    summary       = full.get("summary", {})
    outbound_apis = full.get(
        "inbound_outbound_classification", {}
    ).get("outbound_apis", {}).get("apis", [])

    doc_namespace = f"https://api-discovery-platform/{uuid.uuid4()}"
    doc_name      = f"API-BOM-{engagement_meta.get('app_name', 'target').replace(' ', '-')}"
    created       = _now_iso()

    packages:      List[dict] = []
    relationships: List[dict] = []
    snippets:      List[dict] = []
    doc_spdx_id   = "SPDXRef-DOCUMENT"
    root_spdx_id  = "SPDXRef-Application"

    packages.append({
        "SPDXID":               root_spdx_id,
        "name":                 engagement_meta.get("app_name", "Target Application"),
        "versionInfo":          "1.0",
        "downloadLocation":     "NOASSERTION",
        "filesAnalyzed":        False,
        "supplier":             f"Organization: {engagement_meta.get('client_name', 'Unknown')}",
        "comment":              f"Root application package for API BOM. "
                                f"Engagement: {engagement_meta.get('engagement', '')}. "
                                f"Runtime: {tech_stack.get('runtime', 'unknown')}. "
                                f"Framework: {tech_stack.get('framework', 'unknown')}. "
                                f"Total endpoints: {summary.get('total', 0)}. "
                                f"Shadow: {summary.get('Shadow', 0)}. "
                                f"Rogue: {summary.get('Rogue', 0)}. "
                                f"Secrets: {summary.get('secrets_count', 0)}. "
                                f"OWASP findings: {summary.get('owasp_findings_total', 0)}. "
                                f"CVE findings: {summary.get('cve_findings_total', 0)}.",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {
                "referenceCategory": "OTHER",
                "referenceType":     "api-bom-scan",
                "referenceLocator":  doc_namespace,
            }
        ],
    })

    relationships.append({
        "spdxElementId":      doc_spdx_id,
        "relationshipType":   "DESCRIBES",
        "relatedSpdxElement": root_spdx_id,
    })

    for idx, pkg in enumerate(pkg_deps):
        name    = pkg.get("name") or "unknown"
        version = pkg.get("version") or "unknown"
        eco     = pkg.get("ecosystem") or "generic"
        spdx_id = f"SPDXRef-Pkg-{re.sub(r'[^A-Za-z0-9]', '-', name)}-{idx}"

        purl_map = {
            "npm":    f"pkg:npm/{name}@{version}",
            "pypi":   f"pkg:pypi/{name}@{version}",
            "maven":  f"pkg:maven/{name}@{version}",
            "nuget":  f"pkg:nuget/{name}@{version}",
            "gradle": f"pkg:maven/{name}@{version}",
        }
        purl = purl_map.get(eco, f"pkg:generic/{name}@{version}")

        packages.append({
            "SPDXID":           spdx_id,
            "name":             name,
            "versionInfo":      version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed":    False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType":     "purl",
                    "referenceLocator":  purl,
                }
            ],
            "primaryPackagePurpose": "LIBRARY",
        })

        relationships.append({
            "spdxElementId":      root_spdx_id,
            "relationshipType":   "DYNAMIC_LINK",
            "relatedSpdxElement": spdx_id,
        })

        for cve in cve_summary:
            cve_pkg = cve.get("package") or ""
            if cve_pkg.lower() == name.lower():
                relationships.append({
                    "spdxElementId":      spdx_id,
                    "relationshipType":   "OTHER",
                    "relatedSpdxElement": spdx_id,
                    "comment":            f"CVE: {cve.get('cve')} | CVSS: {cve.get('cvss')} | "
                                          f"{cve.get('desc') or cve.get('description', '')}",
                })

    for idx, ep in enumerate(all_endpoints):
        url         = ep.get("endpoint") or ep.get("url") or ""
        method      = ep.get("method") or "UNKNOWN"
        auth_type   = ep.get("auth_type") or "None detected"
        sensitivity = ep.get("data_sensitivity") or "UNKNOWN"
        cls         = ep.get("classification") or "UNCLASSIFIED"
        module      = ep.get("functional_module") or "Uncategorized"
        owner       = ep.get("inferred_owner") or ""
        risk_score  = ep.get("risk_score", 0)
        risk_band   = ep.get("risk_band") or "LOW"
        owasp_cats  = sorted(set(
            f.get("category") for f in ep.get("owasp_flags", []) if f.get("category")
        ))
        cve_ids     = [c.get("cve") for c in ep.get("cve_findings", []) if c.get("cve")]

        safe_url    = re.sub(r'[^A-Za-z0-9]', '-', url)[:60]
        spdx_id     = f"SPDXRef-API-{idx:04d}-{safe_url}"

        comment_parts = [
            f"Method: {method}",
            f"Classification: {cls}",
            f"Auth: {auth_type}",
            f"Sensitivity: {sensitivity}",
            f"Risk: {risk_band} ({risk_score})",
            f"Module: {module}",
            f"Owner: {owner}",
        ]
        if owasp_cats:
            comment_parts.append(f"OWASP: {', '.join(owasp_cats)}")
        if cve_ids:
            comment_parts.append(f"CVEs: {', '.join(cve_ids)}")

        snippets.append({
            "SPDXID":          spdx_id,
            "snippetFromFile": root_spdx_id,
            "name":            f"{method} {url}",
            "comment":         " | ".join(comment_parts),
            "annotationDate":  created,
            "copyrightText":   "NOASSERTION",
            "licenseInfoInSnippet": ["NOASSERTION"],
            "licenseConcluded": "NOASSERTION",
        })

        relationships.append({
            "spdxElementId":      root_spdx_id,
            "relationshipType":   "CONTAINS",
            "relatedSpdxElement": spdx_id,
            "comment":            f"API endpoint — {cls}",
        })

    for idx, api in enumerate(outbound_apis):
        url         = api.get("url") or api.get("host") or ""
        integration = api.get("integration") or url
        category    = api.get("category") or "external"
        exposure    = api.get("exposure") or "External"
        auth_method = api.get("auth_method") or "unknown"
        risk        = api.get("risk") or "MEDIUM"
        safe_name   = re.sub(r'[^A-Za-z0-9]', '-', integration)[:40]
        spdx_id     = f"SPDXRef-Outbound-{idx:03d}-{safe_name}"

        packages.append({
            "SPDXID":           spdx_id,
            "name":             integration,
            "versionInfo":      "NOASSERTION",
            "downloadLocation": url if url.startswith("http") else "NOASSERTION",
            "filesAnalyzed":    False,
            "comment":          f"Outbound API dependency. Category: {category}. "
                                f"Exposure: {exposure}. Auth: {auth_method}. Risk: {risk}.",
            "primaryPackagePurpose": "APPLICATION",
            "externalRefs": [
                {
                    "referenceCategory": "OTHER",
                    "referenceType":     "outbound-api",
                    "referenceLocator":  url or integration,
                }
            ],
        })

        relationships.append({
            "spdxElementId":      root_spdx_id,
            "relationshipType":   "RUNTIME_DEPENDENCY_OF",
            "relatedSpdxElement": spdx_id,
        })

    spdx_doc = {
        "SPDXID":                doc_spdx_id,
        "spdxVersion":           "SPDX-2.3",
        "creationInfo": {
            "created":           created,
            "creators":          [
                "Tool: api-discovery-platform-2.0.0",
                f"Organization: {engagement_meta.get('client_name', 'Unknown')}",
            ],
            "comment":           f"API Bill of Materials generated by API Discovery Platform. "
                                 f"Engagement: {engagement_meta.get('engagement', '')}.",
        },
        "name":            doc_name,
        "dataLicense":     "CC0-1.0",
        "documentNamespace": doc_namespace,
        "documentDescribes": [root_spdx_id],
        "packages":        packages,
        "snippets":        snippets if snippets else [],
        "relationships":   relationships,
    }

    return spdx_doc


def main():
    parser = argparse.ArgumentParser(
        description="Generate CycloneDX 1.6 and SPDX 2.3 API BOM from api_discovery_full.json"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to api_discovery_full.json",
    )
    parser.add_argument(
        "--bom-dir",
        default=None,
        help="Directory to write BOM files (defaults to same directory as --input)",
    )
    parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx", "both"],
        default="both",
        help="Which BOM format to generate (default: both)",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"ERROR: file not found: {args.input}")
        raise SystemExit(1)

    bom_dir = args.bom_dir or os.path.dirname(os.path.abspath(args.input))
    os.makedirs(bom_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  API BOM Generator")
    print(f"  Input  : {args.input}")
    print(f"  Output : {bom_dir}")
    print(f"  Format : {args.format}")
    print(f"{'='*60}\n")

    print("Loading api_discovery_full.json...")
    full = _load_json(args.input)
    print("  Loaded.")

    engagement_meta = {
        "engagement":   full.get("engagement", "API Discovery & Security Evaluation"),
        "client_name":  full.get("client", "Unknown Client"),
        "app_name":     full.get("app_name") or full.get("client", "Target Application"),
        "generated_at": full.get("generated_at", _now_iso()),
    }

    print(f"\n  Engagement : {engagement_meta['engagement']}")
    print(f"  Client     : {engagement_meta['client_name']}")
    print(f"  App        : {engagement_meta['app_name']}")

    endpoint_count = len(full.get("all_endpoints", []))
    pkg_count      = len(full.get("api_bom", {}).get("package_dependencies", []))
    cve_count      = len(full.get("cve_findings_summary", []))
    outbound_count = len(
        full.get("inbound_outbound_classification", {})
            .get("outbound_apis", {})
            .get("apis", [])
    )
    print(f"\n  Endpoints  : {endpoint_count}")
    print(f"  Packages   : {pkg_count}")
    print(f"  CVEs       : {cve_count}")
    print(f"  Outbound   : {outbound_count}")

    if args.format in ("cyclonedx", "both"):
        print("\nGenerating CycloneDX 1.6 BOM...")
        cdx      = generate_cyclonedx(full, engagement_meta)
        cdx_path = os.path.join(bom_dir, "api_bom.cdx.json")
        with open(cdx_path, "w", encoding="utf-8") as f:
            json.dump(cdx, f, indent=2)
        print(f"  Written    : {cdx_path}")
        print(f"  Components : {len(cdx.get('components', []))}")
        print(f"  Services   : {len(cdx.get('services', []))}")
        print(f"  Vulns      : {len(cdx.get('vulnerabilities', []))}")
        print(f"  Deps       : {len(cdx.get('dependencies', []))}")

    if args.format in ("spdx", "both"):
        print("\nGenerating SPDX 2.3 BOM...")
        spdx      = generate_spdx(full, engagement_meta)
        spdx_path = os.path.join(bom_dir, "api_bom.spdx.json")
        with open(spdx_path, "w", encoding="utf-8") as f:
            json.dump(spdx, f, indent=2)
        print(f"  Written        : {spdx_path}")
        print(f"  Packages       : {len(spdx.get('packages', []))}")
        print(f"  Snippets (APIs): {len(spdx.get('snippets', []))}")
        print(f"  Relationships  : {len(spdx.get('relationships', []))}")

    print(f"\n{'='*60}")
    print("  BOM generation complete")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()