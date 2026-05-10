"""
==============================================
📱 TELEGRAM SESSION API (v3)
==============================================
Handles session extraction, activation, and OTP reading.
Deploy on Render.com (FREE).

FIXED: Uses a persistent event loop so Telethon
clients survive between HTTP requests.
==============================================
"""

import os
import re
import asyncio
import time
import hashlib
import threading
import logging
from flask import Flask, request, jsonify
from telethon import TelegramClient
from telethon.sessions import StringSession

# ===== CONFIG =====
API_ID = int(os.environ.get("API_ID", "0"))
API_HASH = os.environ.get("API_HASH", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "change_me_123")
PORT = int(os.environ.get("PORT", 5000))

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ===== PERSISTENT EVENT LOOP =====
# This loop stays alive across all requests.
# Telethon clients need this to survive between
# extract_start and extract_verify calls.
_loop = asyncio.new_event_loop()

def _run_loop():
    asyncio.set_event_loop(_loop)
    _loop.run_forever()

_bg_thread = threading.Thread(target=_run_loop, daemon=True)
_bg_thread.start()

def run_async(coro, timeout=30):
    """Run async code on the persistent loop."""
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=timeout)

# Storage
active_sessions = {}
pending_logins = {}

def get_session_hash(s):
    return hashlib.md5(s[:50].encode()).hexdigest()[:12]

# =============================================
# HEALTH
# =============================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "active": len(active_sessions),
        "pending": len(pending_logins)
    })

# =============================================
# 1. EXTRACT START — Send Login Code
# =============================================
@app.route("/extract_start", methods=["POST"])
def extract_start():
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403

        phone = data.get("phone", "").strip().replace(" ", "").replace("-", "")
        if not phone or len(phone) < 8:
            return jsonify({"status": "error", "message": "Invalid phone"}), 400
        if not phone.startswith("+"):
            phone = "+" + phone

        login_id = hashlib.md5(f"{phone}{time.time()}".encode()).hexdigest()[:12]

        async def do_send():
            client = TelegramClient(StringSession(), API_ID, API_HASH)
            await client.connect()
            result = await client.send_code_request(phone)
            return client, result.phone_code_hash

        client, phone_code_hash = run_async(do_send())

        pending_logins[login_id] = {
            "client": client,
            "phone": phone,
            "phone_code_hash": phone_code_hash,
            "created_at": time.time()
        }

        # Auto-cleanup after 5 min
        def cleanup():
            time.sleep(300)
            if login_id in pending_logins:
                try:
                    cl = pending_logins[login_id]["client"]
                    run_async(cl.disconnect())
                except: pass
                del pending_logins[login_id]
        threading.Thread(target=cleanup, daemon=True).start()

        return jsonify({"status": "ok", "login_id": login_id, "message": f"Code sent to {phone}"})

    except Exception as e:
        logging.error(f"extract_start error: {e}")
        msg = str(e)
        if "PHONE_NUMBER_INVALID" in msg:
            return jsonify({"status": "error", "message": "Invalid phone number"}), 400
        if "FLOOD" in msg:
            return jsonify({"status": "error", "message": "Too many attempts. Wait."}), 429
        return jsonify({"status": "error", "message": msg}), 500

# =============================================
# 2. EXTRACT VERIFY — Complete Login
# =============================================
@app.route("/extract_verify", methods=["POST"])
def extract_verify():
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403

        login_id = data.get("login_id", "")
        code = str(data.get("code", "")).strip()
        password = data.get("password", "")

        if login_id not in pending_logins:
            return jsonify({"status": "error", "message": "Login expired. Start again."}), 404

        login_data = pending_logins[login_id]
        client = login_data["client"]
        phone = login_data["phone"]
        phone_code_hash = login_data["phone_code_hash"]

        async def do_verify():
            try:
                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
            except Exception as e:
                err = str(e)
                if "SESSION_PASSWORD_NEEDED" in err:
                    if password:
                        await client.sign_in(password=password)
                    else:
                        return "2FA_NEEDED"
                else:
                    raise

            me = await client.get_me()
            session_str = client.session.save()
            await client.disconnect()

            return {
                "session": session_str,
                "phone": me.phone or "Unknown",
                "name": me.first_name or "Unknown",
                "user_id": me.id
            }

        result = run_async(do_verify())

        # Cleanup
        if login_id in pending_logins:
            del pending_logins[login_id]

        if result == "2FA_NEEDED":
            return jsonify({"status": "2fa", "message": "Send the 2FA password too."})

        return jsonify({
            "status": "ok",
            "session": result["session"],
            "phone": result["phone"],
            "name": result["name"],
            "user_id": result["user_id"]
        })

    except Exception as e:
        msg = str(e)
        logging.error(f"extract_verify error: {msg}")
        if "PHONE_CODE_INVALID" in msg:
            return jsonify({"status": "error", "message": "Wrong code."}), 400
        if "PHONE_CODE_EXPIRED" in msg:
            return jsonify({"status": "error", "message": "Code expired. Start again."}), 400
        return jsonify({"status": "error", "message": msg}), 500

# =============================================
# 3. ACTIVATE SESSION
# =============================================
@app.route("/activate", methods=["POST"])
def activate_session():
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403

        session_str = data.get("session", "").strip()
        if not session_str or len(session_str) < 50:
            return jsonify({"status": "error", "message": "Invalid session"}), 400

        sh = get_session_hash(session_str)

        if sh in active_sessions:
            info = active_sessions[sh]
            return jsonify({"status": "ok", "phone": info["phone"], "name": info["name"], "user_id": info["user_id"], "session_hash": sh})

        async def do_activate():
            client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
            await client.connect()
            if not await client.is_user_authorized():
                await client.disconnect()
                return None
            me = await client.get_me()
            return {"client": client, "phone": me.phone or "Unknown", "name": me.first_name or "Unknown", "user_id": me.id, "activated_at": time.time()}

        result = run_async(do_activate())
        if not result:
            return jsonify({"status": "error", "message": "Session expired"}), 400

        active_sessions[sh] = result

        def cleanup():
            time.sleep(600)
            if sh in active_sessions:
                try: run_async(active_sessions[sh]["client"].disconnect())
                except: pass
                del active_sessions[sh]
        threading.Thread(target=cleanup, daemon=True).start()

        return jsonify({"status": "ok", "phone": result["phone"], "name": result["name"], "user_id": result["user_id"], "session_hash": sh})

    except Exception as e:
        logging.error(f"activate error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================
# 4. GET OTP
# =============================================
@app.route("/get_otp", methods=["POST"])
def get_otp():
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403

        sh = data.get("session_hash", "")
        if sh not in active_sessions:
            return jsonify({"status": "error", "message": "Session not active"}), 404

        info = active_sessions[sh]
        client = info["client"]

        async def do_read():
            otps = []
            try:
                async for dlg in client.iter_dialogs(limit=5):
                    try:
                        msgs = await client.get_messages(dlg, limit=5)
                        for m in msgs:
                            if m.text:
                                codes = re.findall(r'\b(\d{4,6})\b', m.text)
                                for c in codes:
                                    if time.time() - m.date.timestamp() < 600:
                                        otps.append({"code": c, "text": m.text[:100]})
                    except: pass
            except: pass
            return otps

        otps = run_async(do_read())

        if otps:
            return jsonify({"status": "ok", "otp": otps[-1]["code"], "full_message": otps[-1]["text"], "phone": info["phone"]})
        else:
            return jsonify({"status": "waiting", "message": "No OTP yet", "phone": info["phone"]})

    except Exception as e:
        logging.error(f"get_otp error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================
# 5. DISCONNECT
# =============================================
@app.route("/disconnect", methods=["POST"])
def disconnect_session():
    try:
        data = request.get_json()
        if data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error"}), 403
        sh = data.get("session_hash", "")
        if sh in active_sessions:
            try: run_async(active_sessions[sh]["client"].disconnect())
            except: pass
            del active_sessions[sh]
        return jsonify({"status": "ok"})
    except:
        return jsonify({"status": "error"}), 500

if __name__ == "__main__":
    print("🚀 Session API v3 starting...")
    app.run(host="0.0.0.0", port=PORT, debug=False)
