import requests
import time
import json
import sys

# The URL of your FastAPI backend
BASE_URL = "http://localhost:8000"

# --- CONFIGURATION ---
GITHUB_TOKEN = ""  # Replace this with your actual token

SCAN_REQUEST = {
    "domain": "http://127.0.0.1:8099",
    "repo_url": "https://github.com/sam143code-cell/test-api",
    "username": "sam143code-cell",
    "access_token": GITHUB_TOKEN,
    "client_name": "Test Client",
    "app_name": "Test App"
}
# ---------------------

POLL_INTERVAL_SECONDS = 10
MAX_WAIT_MINUTES      = 120

def _print(label, value=""):
    # Mask the token in console output for security
    if label.strip() == "access_token" and value:
        value = value[:4] + "********"
    print(f"  {label:<25} {value}")

def _separator(title=""):
    width = 60
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'=' * pad} {title} {'=' * pad}")
    else:
        print("=" * width)

def test_health():
    _separator("HEALTH CHECK")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "ok":
            print("  PASS — server is up")
            return True
        else:
            print(f"  FAIL — unexpected response: {r.status_code} {r.text}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"  FAIL — cannot connect to {BASE_URL}")
        print("  Make sure the server is running:  uvicorn main:app --host 0.0.0.0 --port 8000")
        return False

def test_scan():
    _separator("POST /scan")
    print(f"  Request body:")
    for k, v in SCAN_REQUEST.items():
        _print(f"    {k}", str(v))

    try:
        r = requests.post(
            f"{BASE_URL}/scan",
            json=SCAN_REQUEST,
            timeout=15,
        )
    except Exception as exc:
        print(f"  FAIL — {exc}")
        return None

    if r.status_code == 202:
        data = r.json()
        scan_id = data.get("scan_id")
        print(f"\n  PASS — scan accepted")
        _print("scan_id",    scan_id)
        _print("status",     data.get("status"))
        _print("status_url", data.get("status_url"))
        return scan_id

    elif r.status_code == 409:
        data = r.json()
        print(f"  NOTE — a scan is already running")
        detail = data.get("detail", "")
        existing_id = None
        if "scan_id=" in detail:
            existing_id = detail.split("scan_id=")[1].split(")")[0]
            _print("existing scan_id", existing_id)
        return existing_id

    else:
        print(f"  FAIL — {r.status_code}")
        print(f"  {r.text}")
        return None

def test_poll(scan_id: str):
    _separator("POLLING RESULT")
    url          = f"{BASE_URL}/scan/{scan_id}/result"
    max_polls    = (MAX_WAIT_MINUTES * 60) // POLL_INTERVAL_SECONDS
    poll_count   = 0

    while poll_count < max_polls:
        try:
            r = requests.get(url, timeout=10)
        except Exception as exc:
            print(f"  Poll error: {exc}")
            time.sleep(POLL_INTERVAL_SECONDS)
            poll_count += 1
            continue

        if r.status_code != 200:
            print(f"  FAIL — {r.status_code} {r.text}")
            return False

        data   = r.json()
        status = data.get("status")
        elapsed = poll_count * POLL_INTERVAL_SECONDS

        print(f"  [{elapsed:>4}s]  status = {status}")

        if status == "done":
            _separator("SCAN COMPLETE")

            summary = data.get("summary") or {}
            print("\n  Pipeline Summary:")
            _print("total endpoints",      summary.get("total_endpoints", 0))
            _print("valid",                summary.get("valid", 0))
            _print("shadow",               summary.get("shadow", 0))
            _print("rogue",                summary.get("rogue", 0))
            _print("secrets found",        summary.get("secrets_found", 0))
            _print("outbound apis",        summary.get("outbound_apis", 0))
            _print("high/critical risk",   summary.get("high_critical_risk", 0))
            _print("owasp findings",       summary.get("owasp_findings", 0))
            _print("cve findings",         summary.get("cve_findings", 0))

            output_files = data.get("output_files") or {}
            if output_files:
                print("\n  Output Files:")
                for fname, fpath in output_files.items():
                    _print(fname, fpath)

            _separator()
            print("  RESULT: PASS\n")
            return True

        elif status == "failed":
            _separator("SCAN FAILED")
            _print("error", data.get("error", "unknown"))
            _separator()
            print("  RESULT: FAIL\n")
            return False

        time.sleep(POLL_INTERVAL_SECONDS)
        poll_count += 1

    print(f"\n  TIMEOUT — scan did not complete within {MAX_WAIT_MINUTES} minutes")
    return False

def test_list_scans():
    _separator("GET /scan  (list)")
    try:
        r = requests.get(f"{BASE_URL}/scan", timeout=5)
        if r.status_code == 200:
            scans = r.json()
            print(f"  Total scans in session: {len(scans)}")
            for s in scans:
                print(f"    scan_id={s['scan_id']}  status={s['status']}  domain={s.get('domain')}")
        else:
            print(f"  FAIL — {r.status_code}")
    except Exception as exc:
        print(f"  FAIL — {exc}")

if __name__ == "__main__":
    _separator("API DISCOVERY PLATFORM — TEST")
    print(f"  Target backend: {BASE_URL}")
    print(f"  Scan domain   : {SCAN_REQUEST['domain']}")
    print(f"  Repo URL      : {SCAN_REQUEST['repo_url']}")
    _separator()

    if not test_health():
        sys.exit(1)

    test_list_scans()

    scan_id = test_scan()
    if not scan_id:
        sys.exit(1)

    success = test_poll(scan_id)
    sys.exit(0 if success else 1)