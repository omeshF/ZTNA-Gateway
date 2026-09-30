#!/usr/bin/env python3
"""
render_gateway_server.py - deploy this ONE app to Render for tasks 3 and 4.

It hosts two gateways side by side, on purpose, so the trust-model
difference is visible in the same deployment:

  /vpn/*    Task 3 - classic VPN model. Authenticate ONCE with a shared
            secret; the resulting session can then reach ANY resource
            below. No per-resource check happens after /vpn/connect.

  /ztna/*   Task 4 - zero-trust model. Every request for a resource must
            present an identity + device posture; the gateway checks a
            policy table and, only if that identity is explicitly allowed
            that resource, issues a token scoped to that ONE resource for
            a short time. Nothing is reachable by default.

Deploying to Render
--------------------
1. Put this file and requirements.txt in a GitHub repo.
2. Render dashboard -> New -> Web Service -> connect the repo.
   Build command:  pip install -r requirements.txt
   Start command:  python render_gateway_server.py
3. Render provides HTTPS and sets $PORT automatically; this script reads it.
4. Set an environment variable VPN_PSK to your own shared secret
   (Render dashboard -> Environment). Don't hardcode secrets in real use -
   this lab does it inline only as a documented fallback default.
5. Your app's base URL will be something like:
       https://<your-app-name>.onrender.com
   Use that as RENDER_URL in vpn_render_lab.py and ZTNA_URL in ztna_lab.py.
"""

import os
import secrets
import time
from flask import Flask, request, jsonify, Response

app = Flask(__name__)


# =============================================================================
# Shared "internal resources" both gateways can grant access to.
# =============================================================================

RESOURCES = {
    'finance-app': {'data': 'Q3 revenue: $4.2M (confidential)'},
    'hr-app': {'data': 'Employee headcount: 128'},
    'devtools': {'data': 'CI dashboard: 42 builds green'},
}


# =============================================================================
# /vpn/*  -  Task 3: connect once, reach everything
# =============================================================================

VPN_PSK = os.environ.get('VPN_PSK', 'lab-demo-psk-change-me')
VPN_SESSION_TTL = 300  # seconds

# token -> expiry. In-memory is fine for a lab; a restart clears all sessions.
vpn_sessions = {}


def _vpn_session_valid(token):
    expiry = vpn_sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        vpn_sessions.pop(token, None)
        return False
    return True


@app.route('/vpn/connect', methods=['POST'])
def vpn_connect():
    """Authenticate once with the shared secret; get a broad session token back."""
    body = request.get_json(silent=True) or {}
    if body.get('psk') != VPN_PSK:
        return jsonify(error='authentication failed'), 401

    token = secrets.token_hex(16)
    vpn_sessions[token] = time.time() + VPN_SESSION_TTL
    return jsonify(session_token=token, expires_in=VPN_SESSION_TTL)


@app.route('/vpn/resource/<name>', methods=['GET'])
def vpn_get_resource(name):
    """
    VPN model: any valid session can reach any resource. There is
    deliberately no per-resource check here - once you're "in", you're in.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not _vpn_session_valid(token):
        return jsonify(error='no active VPN session - call /vpn/connect first'), 401

    resource = RESOURCES.get(name)
    if resource is None:
        return jsonify(error='no such resource'), 404
    return jsonify(resource)


@app.route('/vpn/disconnect', methods=['POST'])
def vpn_disconnect():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    vpn_sessions.pop(token, None)
    return jsonify(status='disconnected')


# =============================================================================
# /ztna/*  -  Task 4: nothing reachable by default, decide per request
# =============================================================================

# Who is allowed to reach what, and what device posture they must present.
# Deny by default: anything not listed here is refused.
ZTNA_POLICY = {
    'alice': {'resources': ['finance-app'], 'require_posture': 'compliant'},
    'bob': {'resources': ['devtools', 'hr-app'], 'require_posture': 'compliant'},
}

ZTNA_TOKEN_TTL = 30  # short-lived on purpose - re-authorize often

# token -> {'resource': name, 'expiry': ts}. Each token is scoped to ONE
# resource; it will not work against any other resource, even before expiry.
ztna_tokens = {}

# Rolling audit log of allow/deny decisions - inspect via GET /ztna/audit.
ztna_audit_log = []


def _ztna_log(identity, resource, posture, decision, reason):
    ztna_audit_log.append({
        'time': time.strftime('%H:%M:%S'),
        'identity': identity,
        'resource': resource,
        'posture': posture,
        'decision': decision,
        'reason': reason,
    })
    del ztna_audit_log[:-50]  # keep the last 50 only


@app.route('/ztna/authorize', methods=['POST'])
def ztna_authorize():
    """
    Ask for access to ONE named resource. The gateway checks identity,
    device posture and policy on every single call - there is no broad
    session to fall back on.
    """
    body = request.get_json(silent=True) or {}
    identity = body.get('identity')
    posture = body.get('device_posture')
    resource = body.get('resource')

    policy = ZTNA_POLICY.get(identity)
    if policy is None:
        _ztna_log(identity, resource, posture, 'DENY', 'unknown identity')
        return jsonify(error='denied: unknown identity'), 403

    if resource not in policy['resources']:
        _ztna_log(identity, resource, posture, 'DENY', 'resource not in policy for this identity')
        return jsonify(error='denied: not authorized for this resource'), 403

    if posture != policy['require_posture']:
        _ztna_log(identity, resource, posture, 'DENY', 'device posture check failed')
        return jsonify(error='denied: device posture check failed'), 403

    token = secrets.token_hex(16)
    ztna_tokens[token] = {'resource': resource, 'expiry': time.time() + ZTNA_TOKEN_TTL}
    _ztna_log(identity, resource, posture, 'ALLOW', 'policy + posture check passed')
    return jsonify(access_token=token, resource=resource, expires_in=ZTNA_TOKEN_TTL)


@app.route('/ztna/resource/<name>', methods=['GET'])
def ztna_get_resource(name):
    """
    Even with a valid, unexpired token, this only succeeds if the token was
    scoped to exactly this resource. Try the finance-app token against
    hr-app to see this refuse it.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    entry = ztna_tokens.get(token)

    if entry is None:
        return jsonify(error='no such token - call /ztna/authorize first'), 401
    if time.time() > entry['expiry']:
        ztna_tokens.pop(token, None)
        return jsonify(error='token expired - re-authorize'), 401
    if entry['resource'] != name:
        return jsonify(error='token not scoped to this resource'), 403

    resource = RESOURCES.get(name)
    if resource is None:
        return jsonify(error='no such resource'), 404
    return jsonify(resource)


@app.route('/ztna/audit', methods=['GET'])
def ztna_audit():
    """See the last 50 allow/deny decisions - useful to show students live."""
    return jsonify(ztna_audit_log)


# =============================================================================
# "/"  -  a simple branded landing page (cosmetic only - the login form is
# not wired up; all real authentication happens through the mininet
# scripts, via /vpn/* and /ztna/*). The plain-JSON status check still
# exists too, at /health, for anything that wants machine-readable output.
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify(status='gateway up', resources=list(RESOURCES),
                   endpoints=['/vpn/connect', '/vpn/resource/<name>', '/vpn/disconnect',
                              '/ztna/authorize', '/ztna/resource/<name>', '/ztna/audit'])


_LANDING_PAGE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAB6 Gateway</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --panel-border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --ok: #4ade80;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px;
  }
  .card {
    width: 100%;
    max-width: 360px;
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 14px;
    padding: 32px 28px;
    text-align: center;
  }
  .badge {
    width: 48px; height: 48px; margin: 0 auto 16px;
    border-radius: 10px;
    background: rgba(56, 189, 248, 0.12);
    border: 1px solid rgba(56, 189, 248, 0.35);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem;
  }
  h1 { font-size: 1.25rem; margin: 0 0 4px; }
  p.subtitle { color: var(--muted); font-size: 0.85rem; margin: 0 0 24px; }
  label { display: block; text-align: left; font-size: 0.78rem; color: var(--muted); margin: 14px 0 4px; }
  input {
    width: 100%; padding: 9px 10px; border-radius: 6px;
    border: 1px solid var(--panel-border); background: #0b1220; color: var(--text);
    font-size: 0.9rem;
  }
  input:disabled { opacity: 0.5; cursor: not-allowed; }
  button {
    margin-top: 22px; width: 100%; padding: 10px; border-radius: 6px; border: none;
    background: var(--accent); color: #082032; font-weight: 700; cursor: not-allowed;
    font-size: 0.9rem; opacity: 0.6;
  }
  .status {
    margin-top: 20px; display: inline-flex; align-items: center; gap: 6px;
    font-size: 0.78rem; color: var(--ok); font-weight: 600;
  }
  .status .dot {
    width: 7px; height: 7px; border-radius: 50%; background: var(--ok);
  }
  .note {
    margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--panel-border);
    font-size: 0.74rem; color: var(--muted); line-height: 1.4;
  }
</style>
</head>
<body>

<div class="card">
  <div class="badge">&#128274;</div>
  <h1>LAB6 Gateway</h1>
  <p class="subtitle">7COM2008 &middot; Secure Access Portal</p>

  <label for="username">Username</label>
  <input id="username" type="text" placeholder="alice" disabled>

  <label for="password">Password</label>
  <input id="password" type="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" disabled>

  <button disabled>Sign in</button>

  <div class="status"><span class="dot"></span> Gateway online</div>

  <div class="note">
    Authentication for this lab happens through the mininet scripts
    (VPN and ZTNA), not through this page.
  </div>
</div>

</body>
</html>
'''


@app.route('/', methods=['GET'])
def landing_page():
    return Response(_LANDING_PAGE, mimetype='text/html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
