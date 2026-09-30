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
# "/"  -  a browser-facing landing page, live-testable without mininet at
# all. The old plain-JSON status check still exists too, at /health, in
# case anything (a script, a health-check monitor) wants machine-readable
# output instead of the page below.
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
<title>LAB6 Gateway - VPN vs ZTNA</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --panel-border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --ok: #4ade80;
    --bad: #f87171;
    --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 24px 16px 64px;
  }
  header { max-width: 980px; margin: 0 auto 28px; }
  header h1 { font-size: 1.5rem; margin: 0 0 4px; }
  header p { color: var(--muted); margin: 0; font-size: 0.95rem; }
  .status-badge {
    display: inline-block; margin-top: 10px; padding: 4px 12px;
    background: rgba(74, 222, 128, 0.12); color: var(--ok);
    border: 1px solid rgba(74, 222, 128, 0.35); border-radius: 999px;
    font-size: 0.8rem; font-weight: 600; letter-spacing: 0.02em;
  }
  main { max-width: 980px; margin: 0 auto; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 800px) { main { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--panel-border);
    border-radius: 12px; padding: 20px;
  }
  .card h2 { margin: 0 0 4px; font-size: 1.1rem; }
  .card .tag {
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--accent); font-weight: 700;
  }
  .card p.desc { color: var(--muted); font-size: 0.85rem; margin: 8px 0 16px; }
  label { display: block; font-size: 0.8rem; color: var(--muted); margin: 12px 0 4px; }
  input, select {
    width: 100%; padding: 8px 10px; border-radius: 6px;
    border: 1px solid var(--panel-border); background: #0b1220; color: var(--text);
    font-size: 0.9rem; font-family: inherit;
  }
  button {
    margin-top: 16px; width: 100%; padding: 10px; border-radius: 6px; border: none;
    background: var(--accent); color: #082032; font-weight: 700; cursor: pointer;
    font-size: 0.9rem;
  }
  button:hover { filter: brightness(1.08); }
  button.secondary {
    margin-top: 8px; background: transparent; border: 1px solid var(--panel-border);
    color: var(--text); font-weight: 600;
  }
  .resource-row { display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
  .resource-row button { flex: 1 1 auto; margin-top: 0; padding: 8px; font-size: 0.8rem; }
  .output {
    margin-top: 14px; padding: 10px 12px; border-radius: 6px;
    background: #0b1220; border: 1px solid var(--panel-border);
    font-family: var(--mono); font-size: 0.78rem; white-space: pre-wrap;
    word-break: break-word; min-height: 20px; color: var(--muted);
  }
  .output.ok { color: var(--ok); border-color: rgba(74, 222, 128, 0.35); }
  .output.bad { color: var(--bad); border-color: rgba(248, 113, 113, 0.35); }
  section.audit {
    max-width: 980px; margin: 28px auto 0; background: var(--panel);
    border: 1px solid var(--panel-border); border-radius: 12px; padding: 20px;
  }
  section.audit h2 { margin: 0 0 4px; font-size: 1.05rem; }
  section.audit p.desc { color: var(--muted); font-size: 0.85rem; margin: 4px 0 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--panel-border); }
  th { color: var(--muted); font-weight: 600; font-size: 0.72rem; text-transform: uppercase; }
  td.decision-allow { color: var(--ok); font-weight: 700; }
  td.decision-deny { color: var(--bad); font-weight: 700; }
  footer { max-width: 980px; margin: 28px auto 0; color: var(--muted); font-size: 0.78rem; }
  footer code { font-family: var(--mono); background: #0b1220; padding: 1px 5px; border-radius: 4px; }
</style>
</head>
<body>

<header>
  <h1>LAB6 Gateway</h1>
  <p>One deployment, two trust models: connect-once VPN vs per-resource ZTNA. Test either one directly from this page - no mininet required.</p>
  <span class="status-badge">&#9679; GATEWAY UP</span>
</header>

<main>

  <div class="card">
    <div class="tag">Task 3</div>
    <h2>VPN - connect once, reach everything</h2>
    <p class="desc">Authenticate with the shared secret. The session you get back is NOT checked per resource - anything below is then reachable.</p>

    <label for="vpn-psk">Shared secret (PSK)</label>
    <input id="vpn-psk" type="text" placeholder="lab-demo-psk-change-me" autocomplete="off">
    <button id="vpn-connect-btn" onclick="vpnConnect()">Connect</button>
    <div id="vpn-connect-output" class="output">Not connected yet.</div>

    <div class="resource-row">
      <button class="secondary" onclick="vpnResource('finance-app')">finance-app</button>
      <button class="secondary" onclick="vpnResource('hr-app')">hr-app</button>
      <button class="secondary" onclick="vpnResource('devtools')">devtools</button>
    </div>
    <div id="vpn-resource-output" class="output">Connect first, then try any resource above - all three will work with the same session.</div>
  </div>

  <div class="card">
    <div class="tag">Task 4</div>
    <h2>ZTNA - nothing by default, checked every time</h2>
    <p class="desc">Every request needs an identity + device posture + one named resource. Deny by default: nothing is reachable unless policy explicitly allows it.</p>

    <label for="ztna-identity">Identity</label>
    <select id="ztna-identity">
      <option value="alice">alice</option>
      <option value="bob">bob</option>
      <option value="mallory">mallory (unknown - always denied)</option>
    </select>

    <label for="ztna-posture">Device posture</label>
    <select id="ztna-posture">
      <option value="compliant">compliant</option>
      <option value="jailbroken">jailbroken</option>
    </select>

    <label for="ztna-resource">Resource</label>
    <select id="ztna-resource">
      <option value="finance-app">finance-app</option>
      <option value="hr-app">hr-app</option>
      <option value="devtools">devtools</option>
    </select>

    <button id="ztna-authorize-btn" onclick="ztnaAuthorize()">Authorize</button>
    <div id="ztna-authorize-output" class="output">Not authorized yet.</div>

    <label for="ztna-resource-check">Try the token against</label>
    <select id="ztna-resource-check">
      <option value="finance-app">finance-app</option>
      <option value="hr-app">hr-app</option>
      <option value="devtools">devtools</option>
    </select>
    <button class="secondary" onclick="ztnaResource()">Fetch resource with this token</button>
    <div id="ztna-resource-output" class="output">Authorize first. Then try a DIFFERENT resource here than the one you authorized for, to see the scope refusal.</div>
  </div>

</main>

<section class="audit">
  <h2>Recent gateway decisions</h2>
  <p class="desc">Live from /ztna/audit - every ZTNA allow/deny this gateway has made recently, most recent last. <button class="secondary" style="width:auto;display:inline;padding:4px 10px;margin-left:8px;" onclick="loadAudit()">Refresh</button></p>
  <table>
    <thead><tr><th>Time</th><th>Identity</th><th>Resource</th><th>Posture</th><th>Decision</th><th>Reason</th></tr></thead>
    <tbody id="audit-body"><tr><td colspan="6">Loading...</td></tr></tbody>
  </table>
</section>

<footer>
  Raw JSON endpoints, for scripts: <code>/vpn/connect</code> <code>/vpn/resource/&lt;name&gt;</code>
  <code>/vpn/disconnect</code> <code>/ztna/authorize</code> <code>/ztna/resource/&lt;name&gt;</code>
  <code>/ztna/audit</code> <code>/health</code>. This is a teaching lab, not a production security boundary.
</footer>

<script>
  var vpnToken = null;
  var ztnaToken = null;
  var ztnaTokenResource = null;

  function setOutput(id, obj, ok) {
    var el = document.getElementById(id);
    el.textContent = JSON.stringify(obj, null, 2);
    el.className = 'output ' + (ok ? 'ok' : 'bad');
  }

  function vpnConnect() {
    var psk = document.getElementById('vpn-psk').value;
    fetch('/vpn/connect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({psk: psk})
    })
    .then(function(r) { return r.json().then(function(body) { return {ok: r.ok, body: body}; }); })
    .then(function(res) {
      if (res.ok) {
        vpnToken = res.body.session_token;
        setOutput('vpn-connect-output', res.body, true);
      } else {
        vpnToken = null;
        setOutput('vpn-connect-output', res.body, false);
      }
    })
    .catch(function(err) { setOutput('vpn-connect-output', {error: String(err)}, false); });
  }

  function vpnResource(name) {
    if (!vpnToken) {
      setOutput('vpn-resource-output', {error: 'connect first - no VPN session yet'}, false);
      return;
    }
    fetch('/vpn/resource/' + encodeURIComponent(name), {
      headers: {'Authorization': 'Bearer ' + vpnToken}
    })
    .then(function(r) { return r.json().then(function(body) { return {ok: r.ok, body: body}; }); })
    .then(function(res) { setOutput('vpn-resource-output', res.body, res.ok); })
    .catch(function(err) { setOutput('vpn-resource-output', {error: String(err)}, false); });
  }

  function ztnaAuthorize() {
    var identity = document.getElementById('ztna-identity').value;
    var posture = document.getElementById('ztna-posture').value;
    var resource = document.getElementById('ztna-resource').value;
    fetch('/ztna/authorize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({identity: identity, device_posture: posture, resource: resource})
    })
    .then(function(r) { return r.json().then(function(body) { return {ok: r.ok, body: body}; }); })
    .then(function(res) {
      if (res.ok) {
        ztnaToken = res.body.access_token;
        ztnaTokenResource = res.body.resource;
      } else {
        ztnaToken = null;
        ztnaTokenResource = null;
      }
      setOutput('ztna-authorize-output', res.body, res.ok);
      loadAudit();
    })
    .catch(function(err) { setOutput('ztna-authorize-output', {error: String(err)}, false); });
  }

  function ztnaResource() {
    if (!ztnaToken) {
      setOutput('ztna-resource-output', {error: 'authorize first - no ZTNA token yet'}, false);
      return;
    }
    var name = document.getElementById('ztna-resource-check').value;
    fetch('/ztna/resource/' + encodeURIComponent(name), {
      headers: {'Authorization': 'Bearer ' + ztnaToken}
    })
    .then(function(r) { return r.json().then(function(body) { return {ok: r.ok, body: body}; }); })
    .then(function(res) { setOutput('ztna-resource-output', res.body, res.ok); })
    .catch(function(err) { setOutput('ztna-resource-output', {error: String(err)}, false); });
  }

  function loadAudit() {
    fetch('/ztna/audit')
      .then(function(r) { return r.json(); })
      .then(function(entries) {
        var body = document.getElementById('audit-body');
        if (!entries.length) {
          body.innerHTML = '<tr><td colspan="6">No decisions yet - try ZTNA Authorize above.</td></tr>';
          return;
        }
        var rows = entries.slice().reverse().map(function(e) {
          var cls = e.decision === 'ALLOW' ? 'decision-allow' : 'decision-deny';
          return '<tr><td>' + e.time + '</td><td>' + e.identity + '</td><td>' + e.resource +
                 '</td><td>' + e.posture + '</td><td class="' + cls + '">' + e.decision +
                 '</td><td>' + e.reason + '</td></tr>';
        });
        body.innerHTML = rows.join('');
      })
      .catch(function() {
        document.getElementById('audit-body').innerHTML = '<tr><td colspan="6">Could not load audit log.</td></tr>';
      });
  }

  loadAudit();
</script>
</body>
</html>
'''


@app.route('/', methods=['GET'])
def landing_page():
    return Response(_LANDING_PAGE, mimetype='text/html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
