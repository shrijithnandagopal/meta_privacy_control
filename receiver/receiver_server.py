import os
import requests
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify

META_BASE = os.getenv("META_BASE", "http://localhost:4000").rstrip("/")
META_REQUEST_GATEWAY = f"{META_BASE}/meta/request-gateway"

RECEIVER_PORT = int(os.getenv("RECEIVER_PORT", "5230"))


TEMP_RECEIVED_DATA = {}

app = Flask(__name__)


def safe_json(resp: requests.Response):
    try:
        return True, resp.json()
    except Exception:
        return False, resp.text


def parse_iso_z(s: str):
    if not s or not isinstance(s, str):
        return None

    try:
        if s.endswith("Z"):
            s = s[:-1]

        dt = datetime.fromisoformat(s)
        return dt.replace(tzinfo=timezone.utc)

    except Exception:
        return None


def now_receiver_utc():
    return datetime.now(timezone.utc)


def cleanup_expired_temp_data():
    current_time = now_receiver_utc()
    expired_tokens = []

    for token, record in TEMP_RECEIVED_DATA.items():
        expires_at = record.get("receiver_data_expires_at")

        if expires_at and current_time > expires_at:
            expired_tokens.append(token)

    for token in expired_tokens:
        del TEMP_RECEIVED_DATA[token]

    return expired_tokens


@app.post("/receiver/get-user")
def get_user():
    cleanup_expired_temp_data()

    data = request.get_json(force=True) or {}

    username = (data.get("username") or "").strip()
    purpose = (data.get("purpose") or "identity_verification").strip().lower()

    if not username:
        return jsonify({"error": "username required"}), 400

    gw_resp = requests.post(
        META_REQUEST_GATEWAY,
        json={
            "username": username,
            "purpose": purpose
        },
        timeout=10
    )

    gw_is_json, gw_body = safe_json(gw_resp)

    if gw_resp.status_code != 200:
        return jsonify({
            "step": "request_gateway_failed",
            "meta_status": gw_resp.status_code,
            "meta_is_json": gw_is_json,
            "meta_body": gw_body
        }), gw_resp.status_code

    if not gw_is_json or "gateway_url" not in gw_body:
        return jsonify({
            "step": "bad_gateway_response_from_meta",
            "meta_status": gw_resp.status_code,
            "meta_is_json": gw_is_json,
            "meta_body": gw_body
        }), 502

    gateway_url = gw_body["gateway_url"]
    token_used = gw_body.get("token")
    expires_at = gw_body.get("expires_at")
    issued_at = gw_body.get("issued_at")
    ttl_seconds = gw_body.get("ttl_seconds")
    usage_policy = gw_body.get("usage_policy")
    receiver_retention_policy = gw_body.get("receiver_retention_policy") or {}

    now = now_receiver_utc()
    exp_dt = parse_iso_z(expires_at)

    remaining_seconds = None
    if exp_dt:
        remaining_seconds = max(0, int((exp_dt - now).total_seconds()))

    data_resp = requests.get(gateway_url, timeout=10)
    data_is_json, data_body = safe_json(data_resp)

    if data_resp.status_code != 200:
        return jsonify({
            "step": "gateway_fetch_failed",
            "requested_username": username,
            "purpose": purpose,
            "gateway_url": gateway_url,
            "token_used": token_used,
            "meta_status": data_resp.status_code,
            "meta_is_json": data_is_json,
            "meta_body": data_body
        }), data_resp.status_code

    plaintext = None

    if isinstance(data_body, dict):
        plaintext = data_body.get("user_data") or data_body

        # Meta also sends receiver retention policy inside gateway response.
        gateway_receiver_policy = data_body.get("receiver_retention_policy") or {}
        if gateway_receiver_policy:
            receiver_retention_policy = gateway_receiver_policy

    receiver_data_ttl_seconds = int(
        receiver_retention_policy.get("receiver_data_ttl_seconds", 10)
    )

    receiver_data_received_at = now_receiver_utc()
    receiver_data_expires_at = receiver_data_received_at + timedelta(
        seconds=receiver_data_ttl_seconds
    )

    TEMP_RECEIVED_DATA[token_used] = {
        "requested_username": username,
        "purpose": purpose,
        "user_data": plaintext,
        "receiver_data_received_at": receiver_data_received_at,
        "receiver_data_expires_at": receiver_data_expires_at,
        "receiver_data_ttl_seconds": receiver_data_ttl_seconds
    }

    return jsonify({
        "message": "Receiver fetched decrypted user data and stored it temporarily with expiry control.",
        "requested_username": username,
        "purpose": purpose,
        "gateway_url": gateway_url,
        "token_used": token_used,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "remaining_seconds_now": remaining_seconds,
        "usage_policy": usage_policy,
        "receiver_retention_policy": {
            "receiver_data_ttl_seconds": receiver_data_ttl_seconds,
            "receiver_data_received_at": receiver_data_received_at.isoformat(),
            "receiver_data_expires_at": receiver_data_expires_at.isoformat(),
            "rule": "Receiver will automatically erase this temporary data after expiry."
        },
        "temp_data_view_url": f"http://localhost:{RECEIVER_PORT}/receiver/temp-data/{token_used}",
        "user_data": plaintext
    }), 200


@app.get("/receiver/temp-data/<token>")
def view_temp_data(token: str):
    expired_tokens = cleanup_expired_temp_data()

    if token in expired_tokens:
        return jsonify({
            "error": "Receiver-side temporary data expired and was erased.",
            "token": token,
            "status": "deleted_after_expiry"
        }), 410

    record = TEMP_RECEIVED_DATA.get(token)

    if not record:
        return jsonify({
            "error": "No temporary data found for this token. It may have expired, been erased, or never existed.",
            "token": token
        }), 404

    current_time = now_receiver_utc()
    expires_at = record.get("receiver_data_expires_at")

    if expires_at and current_time > expires_at:
        del TEMP_RECEIVED_DATA[token]

        return jsonify({
            "error": "Receiver-side temporary data expired and was erased.",
            "token": token,
            "status": "deleted_after_expiry"
        }), 410

    remaining_seconds = int((expires_at - current_time).total_seconds()) if expires_at else None

    return jsonify({
        "message": "Temporary receiver-side data is still available.",
        "token": token,
        "remaining_seconds_before_erasure": max(0, remaining_seconds),
        "receiver_data_ttl_seconds": record.get("receiver_data_ttl_seconds"),
        "receiver_data_received_at": record.get("receiver_data_received_at").isoformat(),
        "receiver_data_expires_at": record.get("receiver_data_expires_at").isoformat(),
        "purpose": record.get("purpose"),
        "user_data": record.get("user_data")
    }), 200


@app.get("/receiver/temp-data-status")
def temp_data_status():
    expired_tokens = cleanup_expired_temp_data()

    return jsonify({
        "message": "Temporary receiver storage status.",
        "active_temp_records": len(TEMP_RECEIVED_DATA),
        "expired_records_deleted_now": expired_tokens,
        "active_tokens": list(TEMP_RECEIVED_DATA.keys())
    }), 200


@app.post("/receiver/reuse-token")
def reuse_token():
    data = request.get_json(force=True) or {}

    gateway_url = (data.get("gateway_url") or "").strip()

    if not gateway_url:
        return jsonify({"error": "gateway_url required"}), 400

    resp = requests.get(gateway_url, timeout=10)
    is_json, body = safe_json(resp)

    return jsonify({
        "message": "Attempted reuse of the same gateway URL.",
        "gateway_url": gateway_url,
        "status": resp.status_code,
        "body": body
    }), 200


if __name__ == "__main__":
    print(f"Receiver Server running on http://localhost:{RECEIVER_PORT}")
    print('   POST /receiver/get-user with JSON: {"username":"...", "purpose":"identity_verification"}')
    print('   POST /receiver/reuse-token with JSON: {"gateway_url":"..."}')
    print('   GET  /receiver/temp-data/<token>')
    print('   GET  /receiver/temp-data-status')
    print(f"   Meta base: {META_BASE}")
    app.run(host="0.0.0.0", port=RECEIVER_PORT, debug=True)