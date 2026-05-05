import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from pymongo import MongoClient, ASCENDING
from cryptography.fernet import Fernet
import json

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/")
DB_NAME = os.getenv("DB_NAME", "metapriv")
PORT = int(os.getenv("META_PORT", "4000"))

FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise SystemExit("Missing FERNET_KEY")

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "120"))

USAGE_WINDOW_SECONDS = int(os.getenv("USAGE_WINDOW_SECONDS", "30"))
MAX_USAGE_COUNT = int(os.getenv("MAX_USAGE_COUNT", "1"))


RECEIVER_DATA_TTL_SECONDS = int(os.getenv("RECEIVER_DATA_TTL_SECONDS", "30"))

ALLOWED_PURPOSES = {
    "identity_verification",
    "bank_verification",
    "academic_demo",
    "research_testing"
}

LOOKUP_SECRET = os.getenv("LOOKUP_SECRET")
if not LOOKUP_SECRET:
    raise SystemExit("Missing LOOKUP_SECRET")

fernet = Fernet(FERNET_KEY.encode("utf-8"))

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_col = db["users"]
tokens_col = db["gateway_tokens"]

app = Flask(__name__)


def now_utc() -> datetime:
    return datetime.utcnow()


def encrypt_str(s: str) -> str:
    return fernet.encrypt(s.encode("utf-8")).decode("utf-8")


def decrypt_str(s: str) -> str:
    return fernet.decrypt(s.encode("utf-8")).decode("utf-8")


def make_user_id(username: str, dob: str) -> str:
    raw = f"{username}|{dob}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def username_lookup(username: str) -> str:
    normalized = username.strip().lower().encode("utf-8")
    secret = LOOKUP_SECRET.encode("utf-8")
    return hmac.new(secret, normalized, hashlib.sha256).hexdigest()


def ensure_indexes():
    users_col.create_index([("user_id", ASCENDING)], unique=True)

    users_col.create_index(
        [("username_hash", ASCENDING)],
        unique=True,
        partialFilterExpression={"username_hash": {"$exists": True, "$type": "string"}}
    )

    tokens_col.create_index([("token", ASCENDING)], unique=True)
    tokens_col.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "meta_time_utc": now_utc().isoformat() + "Z"})


@app.post("/meta/user")
def store_user():
    data = request.get_json(force=True) or {}

    username = data.get("username")
    address = data.get("address")
    dob = data.get("dob")
    phone = data.get("phone")

    if not all([username, address, dob, phone]):
        return jsonify({"error": "Missing fields. Required: username, address, dob, phone"}), 400

    user_id = make_user_id(username, dob)
    uhash = username_lookup(username)

    encrypted_user = {
        "user_id": user_id,
        "username_hash": uhash,
        "username_enc": encrypt_str(username),
        "address_enc": encrypt_str(address),
        "dob_enc": encrypt_str(dob),
        "phone_enc": encrypt_str(phone),
        "updated_at": now_utc().isoformat() + "Z"
    }

    users_col.update_one(
        {"user_id": user_id},
        {
            "$set": encrypted_user,
            "$setOnInsert": {"created_at": now_utc()},
        },
        upsert=True
    )

    try:
        with open("encrypted_data.json", "a") as f:
            f.write(json.dumps(encrypted_user) + "\n")
    except Exception as e:
        print("File write error:", str(e))

    return jsonify({
        "message": "User stored securely in MongoDB and saved to encrypted_data.json."
    }), 200


@app.post("/meta/request-gateway")
def request_gateway():
    data = request.get_json(force=True) or {}

    username = data.get("username")
    purpose = (data.get("purpose") or "").strip().lower()

    if not username:
        return jsonify({"error": "username required"}), 400

    if not purpose:
        return jsonify({
            "error": "purpose required",
            "allowed_purposes": sorted(list(ALLOWED_PURPOSES))
        }), 400

    if purpose not in ALLOWED_PURPOSES:
        return jsonify({
            "error": "Purpose not allowed by post-access usage policy",
            "provided_purpose": purpose,
            "allowed_purposes": sorted(list(ALLOWED_PURPOSES))
        }), 403

    uhash = username_lookup(username)
    user = users_col.find_one({"username_hash": uhash})

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id = user["user_id"]

    token = secrets.token_hex(24)
    issued_at = now_utc()
    expires_at = issued_at + timedelta(seconds=TOKEN_TTL_SECONDS)
    usage_window_expires_at = issued_at + timedelta(seconds=USAGE_WINDOW_SECONDS)

    tokens_col.insert_one({
        "token": token,
        "user_id": user_id,
        "used": False,

        "purpose": purpose,
        "usage_count": 0,
        "max_usage_count": MAX_USAGE_COUNT,
        "usage_window_seconds": USAGE_WINDOW_SECONDS,
        "usage_window_expires_at": usage_window_expires_at,

        "receiver_data_ttl_seconds": RECEIVER_DATA_TTL_SECONDS,

        "issued_at": issued_at,
        "expires_at": expires_at,
        "created_at": now_utc()
    })

    return jsonify({
        "gateway_url": f"http://localhost:{PORT}/gateway/{token}",
        "token": token,
        "requested_username": username,
        "issued_at": issued_at.isoformat() + "Z",
        "expires_at": expires_at.isoformat() + "Z",
        "ttl_seconds": TOKEN_TTL_SECONDS,
        "usage_policy": {
            "purpose": purpose,
            "max_usage_count": MAX_USAGE_COUNT,
            "usage_window_seconds": USAGE_WINDOW_SECONDS,
            "rule": "Data can only be released for the approved purpose, within the usage window, and within the maximum usage count."
        },
        "receiver_retention_policy": {
            "receiver_data_ttl_seconds": RECEIVER_DATA_TTL_SECONDS,
            "rule": "Receiver must erase received decrypted data after the expiry time."
        }
    }), 200


@app.get("/gateway/<token>")
def gateway_fetch(token: str):
    tdoc = tokens_col.find_one({"token": token})

    if not tdoc:
        return jsonify({"error": "Invalid token"}), 404

    if tdoc.get("used") is True:
        return jsonify({"error": "Token already used due to post-access one-time usage control"}), 403

    usage_count = int(tdoc.get("usage_count", 0))
    max_usage_count = int(tdoc.get("max_usage_count", 1))

    if usage_count >= max_usage_count:
        return jsonify({
            "error": "Post-access usage limit reached",
            "usage_count": usage_count,
            "max_usage_count": max_usage_count
        }), 403

    usage_window_expires_at = tdoc.get("usage_window_expires_at")

    if isinstance(usage_window_expires_at, datetime):
        if usage_window_expires_at.tzinfo is not None:
            usage_window_expires_at = usage_window_expires_at.replace(tzinfo=None)

        if now_utc() > usage_window_expires_at:
            return jsonify({
                "error": "Post-access usage window expired",
                "usage_window_expired_at": usage_window_expires_at.isoformat() + "Z"
            }), 403

    expires_at = tdoc.get("expires_at")

    if isinstance(expires_at, datetime):
        if expires_at.tzinfo is not None:
            expires_at = expires_at.replace(tzinfo=None)

        if now_utc() > expires_at:
            return jsonify({"error": "Token expired"}), 403

    user_id = tdoc.get("user_id")
    user = users_col.find_one({"user_id": user_id})

    if not user:
        return jsonify({"error": "User not found"}), 404

    tokens_col.update_one(
        {"token": token},
        {
            "$set": {
                "used": True,
                "used_at": now_utc()
            },
            "$inc": {
                "usage_count": 1
            }
        }
    )

    return jsonify({
        "note": "Released via one-time gateway token with Post-Access Data Usage Control.",
        "user_id": user_id,
        "usage_policy_applied": {
            "purpose": tdoc.get("purpose"),
            "usage_count_after_this_access": usage_count + 1,
            "max_usage_count": max_usage_count,
            "usage_window_seconds": tdoc.get("usage_window_seconds")
        },
        "receiver_retention_policy": {
            "receiver_data_ttl_seconds": tdoc.get("receiver_data_ttl_seconds", RECEIVER_DATA_TTL_SECONDS),
            "rule": "Receiver must erase received decrypted data after the expiry time."
        },
        "user_data": {
            "username": decrypt_str(user["username_enc"]),
            "address": decrypt_str(user["address_enc"]),
            "dob": decrypt_str(user["dob_enc"]),
            "phone": decrypt_str(user["phone_enc"])
        }
    }), 200


if __name__ == "__main__":
    ensure_indexes()
    print("Meta Server starting...")
    print(f"   Mongo: {MONGO_URI}  DB: {DB_NAME}")
    print(f"   Token TTL: {TOKEN_TTL_SECONDS}s")
    print(f"   Post-Access Usage Window: {USAGE_WINDOW_SECONDS}s")
    print(f"   Max Usage Count: {MAX_USAGE_COUNT}")
    print(f"   Receiver Data TTL: {RECEIVER_DATA_TTL_SECONDS}s")
    print("   Lookup hash enabled")
    app.run(host="0.0.0.0", port=PORT, debug=True)