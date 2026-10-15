"""
Consolidated test harness: Authentication & Session Security +
Authorization (horizontal + vertical) + Tenant Isolation.

Covers plan phases 3 and 4 in one script, for:
  - jmitchell  (full access)
  - ptest      (full access)
  - lrogahn    (underwriter only)

=====================  FILL THESE IN FOR YOUR APP  =====================
Everything marked TODO below needs a real value captured from browsing
the authenticated app once through browser dev tools / a proxy (ZAP/Burp).
Nothing here will produce valid results until you fill these in.
==========================================================================

Run:
    python auth_authz_tenant_test.py

Required environment variables (set as GitHub Secrets in CI, or env vars
locally — never hardcode credentials):
    TARGET_URL
    JMITCHELL_USER, JMITCHELL_PASS
    PTEST_USER,     PTEST_PASS
    LROGAHN_USER,   LROGAHN_PASS

Only run this against a target you are explicitly authorized to test.
This script performs READ (GET) requests only. Do not add state-changing
(POST/PUT/DELETE) calls unless your written authorization explicitly
covers destructive/state-changing testing.
"""

import json
import os
import sys
from datetime import datetime, timezone

import requests

TARGET_URL = os.environ["TARGET_URL"].rstrip("/")

# --- TODO: real login details, captured from Network tab -----------------
LOGIN_URL = f"{TARGET_URL}/login"                 # TODO: real login POST URL
LOGIN_FIELD_USERNAME = "username"                  # TODO: real field name
LOGIN_FIELD_PASSWORD = "password"                  # TODO: real field name
SESSION_COOKIE_NAME = "ASP.NET_SessionId"           # TODO: real cookie name
LOGGED_IN_MARKER = "Logout"                         # TODO: text only shown when logged in
LOGGED_OUT_MARKER = "Sign In"                       # TODO: text only shown when logged out
LOGOUT_URL = f"{TARGET_URL}/logout"                 # TODO: real logout URL (GET or POST)

# TODO: an endpoint reachable after login, used to test whether an old
# session/cookie still works after logout (expect 401/403/redirect)
AUTHENTICATED_PROBE_URL = f"{TARGET_URL}/api/Account/GetAccountDetails"

# TODO: endpoints that should be full-access-only (admin/underwriter-excluded)
FULL_ACCESS_ONLY_ENDPOINTS = [
    # f"{TARGET_URL}/api/Admin/UserManagement",
    # f"{TARGET_URL}/api/Approvals/GetApprovalQueueInfo",
]

# TODO: endpoints that return one user's own record, for IDOR/tenant testing.
# {id} is substituted with another account's own record ID.
OBJECT_ENDPOINT_TEMPLATES = [
    # f"{TARGET_URL}/api/Account/GetAccountDetails?accountId={{id}}",
    # f"{TARGET_URL}/api/Bonds/GetContractBondRenewalDetails?bondId={{id}}",
]

# TODO: each account's own record ID(s), captured by opening their own record
OWN_RECORD_IDS = {
    "jmitchell": "REPLACE_WITH_JMITCHELL_RECORD_ID",
    "ptest": "REPLACE_WITH_PTEST_RECORD_ID",
    "lrogahn": "REPLACE_WITH_LROGAHN_RECORD_ID",
}
# ---------------------------------------------------------------------------

ACCOUNTS = {
    "jmitchell": {
        "username": os.environ["JMITCHELL_USER"],
        "password": os.environ["JMITCHELL_PASS"],
        "role": "full_access",
    },
    "ptest": {
        "username": os.environ["PTEST_USER"],
        "password": os.environ["PTEST_PASS"],
        "role": "full_access",
    },
    "lrogahn": {
        "username": os.environ["LROGAHN_USER"],
        "password": os.environ["LROGAHN_PASS"],
        "role": "underwriter_only",
    },
}

results = {
    "authentication_session": [],
    "authorization_vertical": [],
    "authorization_horizontal": [],
    "tenant_isolation": [],
    "errors": [],
}


# ---------------------------------------------------------------------------
# Section 1: Authentication & Session Security
# ---------------------------------------------------------------------------

def login(account_key: str) -> requests.Session:
    acct = ACCOUNTS[account_key]
    s = requests.Session()
    resp = s.post(
        LOGIN_URL,
        data={
            LOGIN_FIELD_USERNAME: acct["username"],
            LOGIN_FIELD_PASSWORD: acct["password"],
        },
        allow_redirects=True,
        timeout=15,
    )

    cookie = s.cookies.get(SESSION_COOKIE_NAME)
    logged_in_ok = resp.status_code == 200 and LOGGED_IN_MARKER in resp.text

    if not logged_in_ok:
        results["errors"].append(f"Login did not appear to succeed for {account_key}")

    results["authentication_session"].append(
        {
            "account": account_key,
            "login_status_code": resp.status_code,
            "login_appears_successful": logged_in_ok,
            "session_cookie_present": cookie is not None,
            "set_cookie_header": resp.headers.get("Set-Cookie", ""),
        }
    )
    return s


def test_logout_invalidation(account_key: str, session: requests.Session):
    old_cookie_value = session.cookies.get(SESSION_COOKIE_NAME)

    session.get(LOGOUT_URL, timeout=15)

    # Replay the OLD cookie value against an authenticated endpoint
    stale_session = requests.Session()
    if old_cookie_value:
        stale_session.cookies.set(SESSION_COOKIE_NAME, old_cookie_value)
    resp = stale_session.get(AUTHENTICATED_PROBE_URL, timeout=15)

    still_valid = resp.status_code == 200
    results["authentication_session"].append(
        {
            "account": account_key,
            "test": "post_logout_session_reuse",
            "status_code": resp.status_code,
            "flag": still_valid,  # True = old session still works after logout (BAD)
        }
    )


# ---------------------------------------------------------------------------
# Section 2: Authorization — Vertical (privilege escalation)
# ---------------------------------------------------------------------------

def test_vertical_authorization(session: requests.Session, account_key: str):
    for url in FULL_ACCESS_ONLY_ENDPOINTS:
        resp = session.get(url, timeout=15)
        results["authorization_vertical"].append(
            {
                "endpoint": url,
                "tested_as": account_key,
                "account_role": ACCOUNTS[account_key]["role"],
                "status_code": resp.status_code,
                "flag": resp.status_code == 200,  # True = possible privilege escalation
            }
        )


# ---------------------------------------------------------------------------
# Section 3: Authorization — Horizontal (IDOR) + Tenant isolation
# ---------------------------------------------------------------------------

def test_horizontal_and_tenant(sessions: dict):
    """
    Cross-substitutes each account's own record ID into every other
    account's session, for every OBJECT_ENDPOINT_TEMPLATE. Same mechanism
    covers both "horizontal IDOR between peers" and "cross-tenant access"
    — the distinction is just which accounts represent different tenants
    in your app's data model.
    """
    account_keys = list(sessions.keys())

    for owner_key in account_keys:
        owner_id = OWN_RECORD_IDS.get(owner_key)
        if not owner_id or owner_id.startswith("REPLACE_WITH"):
            continue

        for accessor_key in account_keys:
            if accessor_key == owner_key:
                continue

            for tmpl in OBJECT_ENDPOINT_TEMPLATES:
                url = tmpl.format(id=owner_id)
                resp = sessions[accessor_key].get(url, timeout=15)

                entry = {
                    "endpoint": url,
                    "record_owner": owner_key,
                    "accessed_by": accessor_key,
                    "status_code": resp.status_code,
                    "flag": resp.status_code == 200,  # True = possible IDOR/tenant leak
                }

                results["authorization_horizontal"].append(entry)
                results["tenant_isolation"].append(entry)


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

def _severity(flag: bool) -> str:
    return "FAIL" if flag else "PASS"


def _rows_html(entries: list, columns: list) -> str:
    if not entries:
        return '<tr><td colspan="99" class="empty">No results in this section.</td></tr>'
    rows = []
    for e in entries:
        cells = "".join(f"<td>{e.get(c, '')}</td>" for c in columns)
        flag = e.get("flag")
        row_class = "flagged" if flag else ("ok" if flag is False else "")
        rows.append(f'<tr class="{row_class}">{cells}</tr>')
    return "\n".join(rows)


def generate_html_report(output_path: str):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    auth_cols = ["account", "test", "login_status_code", "status_code", "flag"]
    vert_cols = ["endpoint", "tested_as", "account_role", "status_code", "flag"]
    horiz_cols = ["endpoint", "record_owner", "accessed_by", "status_code", "flag"]

    total_flagged = sum(
        1
        for section in ("authentication_session", "authorization_vertical", "authorization_horizontal")
        for r in results[section]
        if r.get("flag")
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Auth / Authorization / Tenant Isolation Test Report</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .meta {{ color: #666; margin-bottom: 1.5rem; }}
  .summary {{ padding: 1rem; border-radius: 8px; margin-bottom: 2rem;
              background: {"#fde8e8" if total_flagged else "#e8f7ee"};
              border: 1px solid {"#f3a6a6" if total_flagged else "#9fd9b5"}; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 0.9rem; }}
  th {{ background: #f0f0f0; }}
  tr.flagged {{ background: #fde8e8; }}
  tr.ok {{ background: #f3fbf5; }}
  .empty {{ text-align: center; color: #999; font-style: italic; }}
  h2 {{ border-bottom: 2px solid #eee; padding-bottom: 0.3rem; margin-top: 2rem; }}
  .errors {{ color: #b00020; }}
</style>
</head>
<body>
  <h1>Authentication / Authorization / Tenant Isolation Test Report</h1>
  <div class="meta">Generated {timestamp} &middot; Target: {TARGET_URL}</div>

  <div class="summary">
    <strong>{total_flagged} potential issue(s) flagged</strong> across authentication,
    authorization, and tenant isolation checks. Rows highlighted in red indicate
    a flagged result (e.g. a session usable after logout, or an account able to
    reach a record/endpoint it should not).
  </div>

  <h2>1. Authentication &amp; Session Security</h2>
  <table>
    <tr><th>Account</th><th>Test</th><th>Login Status</th><th>Status Code</th><th>Flagged</th></tr>
    {_rows_html(results["authentication_session"], auth_cols)}
  </table>

  <h2>2. Authorization \u2014 Vertical (Privilege Escalation)</h2>
  <table>
    <tr><th>Endpoint</th><th>Tested As</th><th>Role</th><th>Status Code</th><th>Flagged</th></tr>
    {_rows_html(results["authorization_vertical"], vert_cols)}
  </table>

  <h2>3. Authorization \u2014 Horizontal (IDOR) &amp; Tenant Isolation</h2>
  <table>
    <tr><th>Endpoint</th><th>Record Owner</th><th>Accessed By</th><th>Status Code</th><th>Flagged</th></tr>
    {_rows_html(results["authorization_horizontal"], horiz_cols)}
  </table>

  <h2>Errors</h2>
  <p class="errors">{"; ".join(results["errors"]) if results["errors"] else "None"}</p>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)


# ---------------------------------------------------------------------------

def main():
    if not FULL_ACCESS_ONLY_ENDPOINTS and not OBJECT_ENDPOINT_TEMPLATES:
        print(
            "WARNING: FULL_ACCESS_ONLY_ENDPOINTS and OBJECT_ENDPOINT_TEMPLATES "
            "are both empty. Fill in real endpoint URLs at the top of this "
            "script before results will mean anything.",
            file=sys.stderr,
        )

    sessions = {}
    for account_key in ACCOUNTS:
        sessions[account_key] = login(account_key)

    # Vertical: check lrogahn (and, as a sanity check, the full-access accounts)
    # against full-access-only endpoints
    for account_key, session in sessions.items():
        test_vertical_authorization(session, account_key)

    # Horizontal + tenant isolation: cross-substitute record IDs between accounts
    test_horizontal_and_tenant(sessions)

    # Logout/session invalidation — do this last since it logs each account out
    for account_key, session in sessions.items():
        test_logout_invalidation(account_key, session)

    with open("auth_authz_tenant_results.json", "w") as f:
        json.dump(results, f, indent=2)

    report_dir = os.environ.get("REPORT_DIR", "reports")
    os.makedirs(report_dir, exist_ok=True)
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    html_path = os.path.join(report_dir, f"auth-authz-tenant-report-{timestamp_slug}.html")
    generate_html_report(html_path)
    # Also write/overwrite a stable "latest" copy for easy linking
    generate_html_report(os.path.join(report_dir, "auth-authz-tenant-report-latest.html"))
    print(f"HTML report written to {html_path}")

    all_flagged = [
        r
        for section in ("authentication_session", "authorization_vertical", "authorization_horizontal")
        for r in results[section]
        if r.get("flag")
    ]

    if all_flagged:
        print(f"⚠ {len(all_flagged)} potential issue(s) flagged — see auth_authz_tenant_results.json")
    else:
        print("No issues flagged by this pass — see auth_authz_tenant_results.json for full detail")

    if results["errors"]:
        print(f"Errors encountered: {results['errors']}", file=sys.stderr)


if __name__ == "__main__":
    main()
