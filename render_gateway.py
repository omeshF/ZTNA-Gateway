#!/usr/bin/env python3

import os
import secrets
import time
from flask import Flask, request, jsonify

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

@app.route('/', methods=['GET'])
def health():
    return jsonify(status='gateway up', resources=list(RESOURCES),
                   endpoints=['/vpn/connect', '/vpn/resource/<name>', '/vpn/disconnect',
                              '/ztna/authorize', '/ztna/resource/<name>', '/ztna/audit'])


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
