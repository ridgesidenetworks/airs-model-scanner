import os
import time
import tempfile
from uuid import UUID
from typing import Any, Dict, List

import requests
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from model_security_client.api import ModelSecurityAPIClient


# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------

CLIENT_ID = os.getenv("MODEL_SECURITY_CLIENT_ID")
CLIENT_SECRET = os.getenv("MODEL_SECURITY_CLIENT_SECRET")
TSG_ID = os.getenv("TSG_ID")

if not (CLIENT_ID and CLIENT_SECRET and TSG_ID):
    raise ValueError(
        "Missing MODEL_SECURITY_CLIENT_ID, MODEL_SECURITY_CLIENT_SECRET, or TSG_ID "
        "environment variables."
    )

# Your local security group UUID for model scans (from Strata Cloud Manager)
LOCAL_SCAN_GROUP = UUID(os.getenv("LOCAL_SCAN_GROUP_UUID"))

AIMS_BASE_URL = "https://api.sase.paloaltonetworks.com/aims"
TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"

# Model Security SDK client
client = ModelSecurityAPIClient(base_url=AIMS_BASE_URL)

# Simple in-memory token cache for AIMS data API
_token_cache: Dict[str, Any] = {
    "access_token": None,
    "expires_at": 0.0,  # epoch seconds
}


# ---------------------------------------------------------------------------
# Helpers: token + violations
# ---------------------------------------------------------------------------

def get_access_token() -> str:
    """
    Return a valid access token for AIMS data APIs.
    Uses client_credentials with scope=tsg_id:<TSG_ID>.
    Caches token until expiry (with small safety margin).
    """
    now = time.time()
    # Re-use token if still valid (60s safety window)
    if _token_cache["access_token"] and _token_cache["expires_at"] - 60 > now:
        return _token_cache["access_token"]

    payload = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{TSG_ID}",
    }

    resp = requests.post(TOKEN_URL, data=payload, auth=(CLIENT_ID, CLIENT_SECRET))
    if resp.status_code != 200:
        raise RuntimeError(
            f"Failed to obtain access token: {resp.status_code} {resp.text}"
        )

    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError("Token response missing access_token")

    # Default to 15 minutes if expires_in is absent
    expires_in = data.get("expires_in", 900)
    _token_cache["access_token"] = token
    _token_cache["expires_at"] = now + expires_in

    return token


def fetch_rule_violations(scan_id: str) -> List[Dict[str, Any]]:
    """
    Fetch rule violations for a given scan UUID from the AIMS data API.
    Automatically refreshes token on 401 once.
    """
    def _do_request(token: str) -> requests.Response:
        url = f"{AIMS_BASE_URL}/data/v1/scans/{scan_id}/rule-violations"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        params = {"skip": 0, "limit": 100}
        return requests.get(url, headers=headers, params=params)

    token = get_access_token()
    resp = _do_request(token)

    # If token is stale, refresh once and retry
    if resp.status_code == 401:
        _token_cache["access_token"] = None
        token = get_access_token()
        resp = _do_request(token)

    if resp.status_code != 200:
        raise RuntimeError(
            f"Failed to fetch rule violations: {resp.status_code} {resp.text}"
        )

    data = resp.json()
    return data.get("violations", [])


# ---------------------------------------------------------------------------
# FastAPI app setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Prisma AIRS · Model Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can tighten this if you want
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# UI (GET /)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    # Single-page Prisma-style UI
    return HTMLResponse(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Prisma AIRS · Model Security Scanner</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {
      --bg: #020617;
      --bg-elevated: #020817;
      --card: #020617;
      --card-border: rgba(148, 163, 184, 0.35);
      --accent: #22d3ee;
      --accent-soft: rgba(45, 212, 191, 0.12);
      --danger: #f97373;
      --danger-soft: rgba(248, 113, 113, 0.12);
      --text: #e5e7eb;
      --subtle: #9ca3af;
      --muted: #6b7280;
      --pill-bg: #020617;
      --pill-border: rgba(148, 163, 184, 0.4);
      --badge-block: #fee2e2;
      --badge-block-text: #b91c1c;
      --badge-ok: #dcfce7;
      --badge-ok-text: #166534;
      --badge-warn: #fef9c3;
      --badge-warn-text: #854d0e;
      --scroll-track: rgba(15,23,42,0.9);
      --scroll-thumb: rgba(148,163,184,0.9);
      --shadow-soft: 0 22px 45px rgba(15,23,42,0.88);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top left, #0f172a 0, #020617 45%, #000 100%);
      color: var(--text);
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding: 32px 16px 48px;
    }

    .shell {
      width: 100%;
      max-width: 1220px;
      background: radial-gradient(circle at top left, rgba(56,189,248,0.08), transparent 55%) var(--bg-elevated);
      border-radius: 32px;
      padding: 28px 28px 32px;
      border: 1px solid rgba(148, 163, 184, 0.3);
      box-shadow: var(--shadow-soft);
      position: relative;
      overflow: hidden;
    }

    .shell::before {
      content: "";
      position: absolute;
      inset: -40%;
      background:
        radial-gradient(circle at 0% 0%, rgba(56,189,248,0.12), transparent 55%),
        radial-gradient(circle at 100% 10%, rgba(129,140,248,0.10), transparent 55%);
      opacity: 0.9;
      pointer-events: none;
      z-index: -1;
    }

    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 20px;
    }

    .logo-row {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .logo-circle {
      width: 38px;
      height: 38px;
      border-radius: 999px;
      background: radial-gradient(circle at 30% 0%, #e0f2fe, #22d3ee 45%, #0ea5e9 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 18px 45px rgba(8,47,73,0.9);
      color: #0f172a;
      font-weight: 700;
      font-size: 20px;
    }

    .title-block h1 {
      font-size: 22px;
      letter-spacing: 0.04em;
      margin: 0 0 4px;
    }

    .title-block p {
      margin: 0;
      color: var(--muted);
      font-size: 13px;
    }

    .pill-badge {
      padding: 6px 11px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.45);
      background: radial-gradient(circle at 0% 0%, rgba(148,163,184,0.5), transparent 55%) var(--pill-bg);
      font-size: 11px;
      color: var(--subtle);
      text-transform: uppercase;
      letter-spacing: 0.16em;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .pill-badge-dot {
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: #22c55e;
      box-shadow: 0 0 0 4px rgba(34,197,94,0.25);
    }

    main {
      display: flex;
      flex-direction: column;
      gap: 22px;
    }

    .grid-main {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.1fr);
      gap: 22px;
      align-items: flex-start;
    }

    .grid-bottom {
      display: grid;
      grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr);
      gap: 22px;
      align-items: stretch;
    }

    .card {
      background: linear-gradient(to bottom right, rgba(15,23,42,0.9), rgba(15,23,42,0.98));
      border-radius: 22px;
      border: 1px solid var(--card-border);
      padding: 18px 18px 18px;
      box-shadow: 0 18px 45px rgba(15,23,42,0.95);
      position: relative;
      overflow: hidden;
    }

    .card::before {
      content: "";
      position: absolute;
      inset: -40%;
      background:
        radial-gradient(circle at top left, rgba(56,189,248,0.10), transparent 55%),
        radial-gradient(circle at bottom right, rgba(129,140,248,0.06), transparent 55%);
      opacity: 0.85;
      pointer-events: none;
      z-index: -1;
    }

    .card h2 {
      margin: 0 0 6px;
      font-size: 16px;
      letter-spacing: 0.03em;
    }

    .card p {
      margin: 0;
      font-size: 13px;
      color: var(--subtle);
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 14px;
    }

    .section-header small {
      font-size: 12px;
      color: var(--muted);
    }

    .upload-row {
      margin-top: 12px;
      display: flex;
      gap: 10px;
      align-items: center;
    }

    input[type="file"] {
      font-size: 13px;
      color: var(--text);
      padding: 7px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.6);
      background: rgba(15,23,42,0.95);
    }

    input[type="file"]::-webkit-file-upload-button {
      border: none;
      border-radius: 999px;
      padding: 7px 12px;
      margin-right: 8px;
      background: rgba(15,23,42,0.9);
      color: var(--subtle);
      font-size: 12px;
      cursor: pointer;
    }

    button.primary {
      border: none;
      border-radius: 999px;
      padding: 9px 22px;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      cursor: pointer;
      background: radial-gradient(circle at top left, #e0f2fe, #22d3ee 45%, #0ea5e9 100%);
      color: #0f172a;
      box-shadow: 0 18px 35px rgba(8,47,73,0.9);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    button.primary:disabled {
      opacity: 0.55;
      cursor: wait;
      box-shadow: none;
    }

    .pill-status {
      margin-top: 14px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(220,38,38,0.5);
      background: radial-gradient(circle at 0% 0%, rgba(248,113,113,0.18), transparent 55%) var(--danger-soft);
      color: var(--danger);
      font-size: 12px;
      font-weight: 500;
    }

    .pill-status-dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #ef4444;
      box-shadow: 0 0 0 4px rgba(248,113,113,0.35);
    }

    .pill-status-ok {
      border-color: rgba(34,197,94,0.6);
      background: radial-gradient(circle at 0% 0%, rgba(34,197,94,0.22), transparent 55%) rgba(22,163,74,0.12);
      color: #bbf7d0;
    }

    .pill-status-ok .pill-status-dot {
      background: #22c55e;
      box-shadow: 0 0 0 4px rgba(22,163,74,0.4);
    }

    .metric-row {
      margin-top: 16px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0,1fr));
      gap: 10px;
    }

    .metric-pill {
      border-radius: 18px;
      border: 1px solid var(--pill-border);
      background: linear-gradient(to bottom right, rgba(15,23,42,0.96), rgba(15,23,42,0.99));
      padding: 10px 12px 9px;
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }

    .metric-pill strong {
      display: block;
      margin-top: 6px;
      font-size: 18px;
      letter-spacing: 0.02em;
      color: #e5f6ff;
    }

    .metric-pill span.sub {
      font-size: 11px;
      color: var(--muted);
    }

    .scan-meta {
      margin-top: 12px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap: 10px 30px;
      font-size: 12px;
      color: var(--subtle);
    }

    .scan-meta dt {
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 11px;
      margin-bottom: 3px;
      color: var(--muted);
    }

    .scan-meta dd {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      color: #e5e7eb;
      word-break: break-all;
    }

    .stats-row {
      margin-top: 16px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0,1fr));
      gap: 10px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
    }

    .stats-pill {
      border-radius: 18px;
      border: 1px solid var(--pill-border);
      background: linear-gradient(to bottom right, rgba(15,23,42,0.96), rgba(15,23,42,0.99));
      padding: 10px 12px 8px;
    }

    .stats-pill strong {
      display: block;
      margin-top: 6px;
      font-size: 18px;
      letter-spacing: 0.02em;
      color: #e5f6ff;
    }

    .stats-pill span.sub {
      font-size: 11px;
      color: var(--muted);
    }

    /* Violations */

    .violations-summary-row {
      margin-top: 8px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
    }

    .viol-count-pill {
      border-radius: 999px;
      border: 1px solid var(--pill-border);
      background: rgba(15,23,42,0.96);
      padding: 6px 10px 5px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .viol-count-pill strong {
      font-size: 13px;
      color: #e5f6ff;
    }

    .viol-count-pill.blocking {
      border-color: rgba(248,113,113,0.6);
      background: radial-gradient(circle at 0% 0%, rgba(248,113,113,0.18), transparent 55%) rgba(15,23,42,0.96);
    }

    .viol-count-pill.warning {
      border-color: rgba(234,179,8,0.7);
      background: radial-gradient(circle at 0% 0%, rgba(234,179,8,0.18), transparent 55%) rgba(15,23,42,0.96);
    }

    .viol-count-pill.other {
      border-color: rgba(148,163,184,0.7);
    }

    .viol-list {
      margin-top: 14px;
      max-height: 270px;
      overflow: auto;
      padding-right: 4px;
    }

    .viol-card {
      border-radius: 16px;
      border: 1px solid rgba(148,163,184,0.55);
      background: radial-gradient(circle at 0% 0%, rgba(15,23,42,0.9), transparent 55%) rgba(15,23,42,0.98);
      padding: 10px 11px 10px;
      font-size: 12px;
      margin-bottom: 8px;
    }

    .viol-header {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: center;
      margin-bottom: 4px;
    }

    .viol-title {
      font-weight: 500;
      color: #e5e7eb;
    }

    .badge {
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-weight: 600;
    }

    .badge.blocking {
      background: var(--badge-block);
      color: var(--badge-block-text);
    }

    .badge.ok {
      background: var(--badge-ok);
      color: var(--badge-ok-text);
    }

    .badge.warning {
      background: var(--badge-warn);
      color: var(--badge-warn-text);
    }

    .viol-body {
      color: var(--subtle);
      line-height: 1.4;
    }

    .viol-meta {
      margin-top: 6px;
      font-size: 11px;
      color: var(--muted);
    }

    .viol-meta code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 11px;
      background: rgba(15,23,42,0.95);
      padding: 1px 5px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.4);
    }

    /* Raw JSON */

    pre {
      margin: 0;
      padding: 10px 12px;
      border-radius: 14px;
      background: radial-gradient(circle at 0% 0%, rgba(15,23,42,0.85), transparent 55%) #020617;
      border: 1px solid rgba(30,64,175,0.8);
      color: #e5e7eb;
      font-size: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      max-height: 300px;
      overflow: auto;
    }

    pre::-webkit-scrollbar,
    .viol-list::-webkit-scrollbar {
      width: 8px;
    }

    pre::-webkit-scrollbar-track,
    .viol-list::-webkit-scrollbar-track {
      background: var(--scroll-track);
    }

    pre::-webkit-scrollbar-thumb,
    .viol-list::-webkit-scrollbar-thumb {
      background-color: var(--scroll-thumb);
      border-radius: 4px;
    }

    .muted {
      color: var(--muted);
      font-size: 12px;
    }

    @media (max-width: 940px) {
      .grid-main,
      .grid-bottom {
        grid-template-columns: minmax(0,1fr);
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div class="logo-row">
        <div class="logo-circle">P</div>
        <div class="title-block">
          <h1>Prisma AIRS · Model Security Scanner</h1>
          <p>Local AI model scanner.</p>
        </div>
      </div>
      <div class="pill-badge">
        <span class="pill-badge-dot"></span>
        LIVE · MODEL SECURITY
      </div>
    </header>

    <main>
      <div class="grid-main">
        <!-- Upload + Outcome -->
        <section class="card">
          <div class="section-header">
            <div>
              <h2>Upload &amp; Scan</h2>
              <p>Upload a zipped HuggingFace model folder or other local model artifact.</p>
            </div>
          </div>

          <form id="uploadForm" class="upload-row">
            <input id="fileInput" type="file" name="file" required />
            <button id="scanButton" class="primary" type="submit">
              Run Prisma AIRS Scan
            </button>
          </form>

          <div id="outcomePill" class="pill-status" style="display:none;">
            <span class="pill-status-dot"></span>
            <span id="outcomeText">Blocked</span>
          </div>

          <div class="metric-row">
            <div class="metric-pill">
              PASSED RULES
              <strong><span id="passedCount">0</span> / <span id="totalRules">0</span></strong>
              <span class="sub">Policies satisfied</span>
            </div>
            <div class="metric-pill">
              FAILED RULES
              <strong><span id="failedCount">0</span> / <span id="totalRules2">0</span></strong>
              <span class="sub">Blocking &amp; warning</span>
            </div>
            <div class="metric-pill">
              PASS RATE
              <strong><span id="passRate">0.0</span>%</strong>
              <span class="sub">Overall policy health</span>
            </div>
          </div>
        </section>

        <!-- Scan details -->
        <section class="card">
          <div class="section-header">
            <div>
              <h2>Scan Details</h2>
              <p>High-level metadata for the most recent scan.</p>
            </div>
          </div>

          <dl class="scan-meta">
            <div>
              <dt>Scan ID</dt>
              <dd id="scanId">–</dd>
            </div>
            <div>
              <dt>TSG ID</dt>
              <dd id="tsgId">–</dd>
            </div>
            <div>
              <dt>Security Group</dt>
              <dd id="securityGroup">–</dd>
            </div>
            <div>
              <dt>Scanner Version</dt>
              <dd id="scannerVersion">–</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd id="createdAt">–</dd>
            </div>
            <div>
              <dt>Formats</dt>
              <dd id="formats">–</dd>
            </div>
          </dl>

          <div class="stats-row">
            <div class="stats-pill">
              FILES SCANNED
              <strong><span id="filesScanned">0</span></strong>
              <span class="sub">Artifacts inspected</span>
            </div>
            <div class="stats-pill">
              FILES SKIPPED
              <strong><span id="filesSkipped">0</span></strong>
              <span class="sub">Unscannable</span>
            </div>
            <div class="stats-pill">
              RULES ENABLED
              <strong><span id="rulesEnabled">0</span></strong>
              <span class="sub">Active policies</span>
            </div>
          </div>
        </section>
      </div>

      <!-- Violations + Raw JSON -->
      <div class="grid-bottom">
        <section class="card">
          <div class="section-header">
            <div>
              <h2>Rule Violations</h2>
              <p>Blocking and warning findings from Prisma AIRS Model Security.</p>
            </div>
          </div>

          <div id="violationsSummary" class="violations-summary-row">
            <span class="muted">Run a scan to view violations.</span>
          </div>

          <div id="violationsList" class="viol-list"></div>
        </section>

        <section class="card">
          <div class="section-header">
            <div>
              <h2>Raw JSON Response</h2>
              <p>Direct output from the Prisma Model Security API (Model Security SDK).</p>
            </div>
          </div>
          <pre id="rawJson" class="muted">// Scan results will appear here once a model has been analyzed.</pre>
        </section>
      </div>
    </main>
  </div>

  <script>
    const form = document.getElementById("uploadForm");
    const fileInput = document.getElementById("fileInput");
    const scanButton = document.getElementById("scanButton");
    const outcomePill = document.getElementById("outcomePill");
    const outcomeText = document.getElementById("outcomeText");

    const passedCountEl = document.getElementById("passedCount");
    const failedCountEl = document.getElementById("failedCount");
    const totalRulesEl = document.getElementById("totalRules");
    const totalRules2El = document.getElementById("totalRules2");
    const passRateEl = document.getElementById("passRate");

    const scanIdEl = document.getElementById("scanId");
    const tsgIdEl = document.getElementById("tsgId");
    const securityGroupEl = document.getElementById("securityGroup");
    const scannerVersionEl = document.getElementById("scannerVersion");
    const createdAtEl = document.getElementById("createdAt");
    const formatsEl = document.getElementById("formats");
    const filesScannedEl = document.getElementById("filesScanned");
    const filesSkippedEl = document.getElementById("filesSkipped");
    const rulesEnabledEl = document.getElementById("rulesEnabled");

    const rawJsonEl = document.getElementById("rawJson");
    const violationsSummaryEl = document.getElementById("violationsSummary");
    const violationsListEl = document.getElementById("violationsList");

    function setOutcome(evalOutcome) {
      if (!evalOutcome) {
        outcomePill.style.display = "none";
        return;
      }
      const text = String(evalOutcome);
      const isAllowed = text.toUpperCase().includes("ALLOW") || text.toUpperCase().includes("PASS");
      outcomePill.style.display = "inline-flex";
      if (isAllowed) {
        outcomePill.classList.add("pill-status-ok");
        outcomePill.classList.remove("pill-status");
        outcomeText.textContent = "Allowed";
      } else {
        outcomePill.classList.add("pill-status");
        outcomePill.classList.remove("pill-status-ok");
        outcomeText.textContent = "Blocked";
      }
    }

    function renderViolations(data) {
      const violations = data.violations || [];
      const counts = data.violations_counts || {};

      if (!violations.length) {
        violationsSummaryEl.innerHTML = '<span class="muted">No rule violations were reported for this scan.</span>';
        violationsListEl.innerHTML = "";
        return;
      }

      const blockingCount = counts.BLOCKING || 0;
      const warningCount = counts.WARNING || 0;
      const otherCount = (counts.OTHER || 0) + (counts.INFO || 0);

      let summaryHtml = "";
      summaryHtml += `<div class="viol-count-pill blocking"><span>Blocking</span><strong>${blockingCount}</strong></div>`;
      summaryHtml += `<div class="viol-count-pill warning"><span>Warning</span><strong>${warningCount}</strong></div>`;
      summaryHtml += `<div class="viol-count-pill other"><span>Other</span><strong>${otherCount}</strong></div>`;
      violationsSummaryEl.innerHTML = summaryHtml;

      const cards = violations.map(v => {
        const state = (v.rule_instance_state || "").toUpperCase();
        let badgeClass = "other";
        let badgeLabel = state || "OTHER";

        if (state === "BLOCKING") {
          badgeClass = "blocking";
        } else if (state === "WARNING") {
          badgeClass = "warning";
        }

        const ruleName = v.rule_name || "Unnamed rule";
        const threatDesc = v.threat_description || "";
        const description = v.description || "";
        const file = v.file || "";
        const moduleName = v.module || "";
        const operator = v.operator || "";

        let metaBits = [];
        if (file) metaBits.push(`File <code>${file}</code>`);
        if (moduleName) metaBits.push(`Module <code>${moduleName}</code>`);
        if (operator) metaBits.push(`Operator <code>${operator}</code>`);

        const metaLine = metaBits.length ? metaBits.join(" · ") : "";

        return `
          <div class="viol-card">
            <div class="viol-header">
              <div class="viol-title">${ruleName}</div>
              <span class="badge ${badgeClass}">${badgeLabel}</span>
            </div>
            <div class="viol-body">
              ${threatDesc ? `<div>${threatDesc}</div>` : ""}
              ${description ? `<div style="margin-top:3px;">${description}</div>` : ""}
            </div>
            ${metaLine ? `<div class="viol-meta">${metaLine}</div>` : ""}
          </div>
        `;
      });

      violationsListEl.innerHTML = cards.join("");
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!fileInput.files.length) return;

      const data = new FormData();
      data.append("file", fileInput.files[0]);

      scanButton.disabled = true;
      scanButton.textContent = "Scanning…";
      outcomePill.style.display = "none";
      rawJsonEl.textContent = "// Scanning model with Prisma AIRS…";

      try {
        const resp = await fetch("/scan-model", {
          method: "POST",
          body: data
        });

        const json = await resp.json();

        rawJsonEl.textContent = JSON.stringify(json, null, 2);

        if (!resp.ok) {
          outcomePill.style.display = "inline-flex";
          outcomePill.classList.add("pill-status");
          outcomePill.classList.remove("pill-status-ok");
          outcomeText.textContent = "Scan Error";
          violationsSummaryEl.innerHTML = '<span class="muted">Scan failed. See Raw JSON for details.</span>';
          violationsListEl.innerHTML = "";
          return;
        }

        const evalSummary = json.eval_summary || {};
        const total = evalSummary.total_rules || json.rules_summary?.total || 0;
        const passed = evalSummary.rules_passed || json.rules_summary?.passed || 0;
        const failed = evalSummary.rules_failed || json.rules_summary?.failed || 0;
        const rate = total > 0 ? (passed / total * 100) : 0;

        passedCountEl.textContent = passed;
        failedCountEl.textContent = failed;
        totalRulesEl.textContent = total;
        totalRules2El.textContent = total;
        passRateEl.textContent = rate.toFixed(1);

        setOutcome(json.eval_outcome);

        scanIdEl.textContent = json.uuid || "–";
        tsgIdEl.textContent = json.tsg_id || "–";
        securityGroupEl.textContent = json.security_group_uuid || "–";
        scannerVersionEl.textContent = json.scanner_version || "–";
        createdAtEl.textContent = json.created_at || "–";
        formatsEl.textContent = (json.model_formats || []).join(", ") || "–";
        filesScannedEl.textContent = json.total_files_scanned ?? "0";
        filesSkippedEl.textContent = json.total_files_skipped ?? "0";
        rulesEnabledEl.textContent = json.enabled_rule_count_snapshot ?? "0";

        renderViolations(json);
      } catch (err) {
        console.error(err);
        rawJsonEl.textContent = "// Error performing scan. See browser console for details.";
        outcomePill.style.display = "inline-flex";
        outcomePill.classList.add("pill-status");
        outcomePill.classList.remove("pill-status-ok");
        outcomeText.textContent = "Scan Error";
        violationsSummaryEl.innerHTML = '<span class="muted">Scan failed. See Raw JSON for details.</span>';
        violationsListEl.innerHTML = "";
      } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Run Prisma AIRS Scan";
      }
    });
  </script>
</body>
</html>
        """
    )


# ---------------------------------------------------------------------------
# API: Scan model
# ---------------------------------------------------------------------------

@app.post("/scan-model")
async def scan_model(file: UploadFile = File(...)) -> JSONResponse:
    """
    Accepts an uploaded model artifact (e.g., zipped HF folder or .pkl/.bin),
    runs Prisma AIRS Model Security scan, then automatically fetches
    rule-violation details and returns everything as JSON.
    """
    # Save upload to a temp file
    suffix = os.path.splitext(file.filename or "")[-1] or ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {exc}")

    try:
        # Run scan using the SDK
        result = client.scan(
            security_group_uuid=LOCAL_SCAN_GROUP,
            model_path=tmp_path,
        )

        # Convert result to plain dict
        scan_dict = jsonable_encoder(result)

        # Rule summary
        eval_summary = getattr(result, "eval_summary", None)
        if eval_summary is not None:
            passed = getattr(eval_summary, "rules_passed", 0)
            failed = getattr(eval_summary, "rules_failed", 0)
            total = getattr(eval_summary, "total_rules", 0)
        else:
            passed = failed = total = 0

        rules_summary = {
            "passed": passed,
            "failed": failed,
            "total": total,
        }

        # Fetch rule violations via data API
        violations: List[Dict[str, Any]] = []
        violations_counts: Dict[str, int] = {}
        try:
            scan_id_str = str(result.uuid)
            violations = fetch_rule_violations(scan_id_str)

            grouped: Dict[str, int] = {}
            for v in violations:
                state = (v.get("rule_instance_state") or "OTHER").upper()
                grouped[state] = grouped.get(state, 0) + 1
            violations_counts = grouped
        except Exception as exc:
            scan_dict["violations_error"] = str(exc)

        scan_dict["rules_summary"] = rules_summary
        scan_dict["violations"] = violations
        scan_dict["violations_counts"] = violations_counts

        return JSONResponse(scan_dict)

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Model scan failed: {exc}")
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
