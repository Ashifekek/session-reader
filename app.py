"""
==============================================
📱 TELEGRAM SESSION API (v2)
==============================================
Handles:
  1. Session EXTRACTION (admin adds accounts from phone)
  2. Session ACTIVATION (show phone number to customer)
  3. OTP READING (read incoming OTP for customer)

Deploy on Render.com (FREE). Your TBC bot calls this API.
==============================================
"""

import os
import re
import asyncio
import time
import json
import logging
import hashlib
import threading
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

# Active session clients
active_sessions = {}

# Pending login flows (admin extracting sessions)
pending_logins = {}

def get_session_hash(session_str):
    return hashlib.md5(session_str[:50].encode()).hexdigest()[:12]

def run_async(coro):
    """Helper to run async code in sync Flask context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

# =============================================
# HEALTH CHECK
# =============================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "active_sessions": len(active_sessions),
        "pending_logins": len(pending_logins)
    })

# =============================================
# 1. EXTRACT SESSION — Step 1: Send Login Code
# =============================================
@app.route("/extract_start", methods=["POST"])
def extract_start():
    """
    Admin sends phone number → we send Telegram login code to that phone.
    
    POST: {"phone": "+919876543210", "secret": "..."}
    Returns: {"status": "ok", "phone_hash": "abc123", "login_id": "xyz789"}
    """
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403
        
        phone = data.get("phone", "").strip()
        if not phone or len(phone) < 8:
            return jsonify({"status": "error", "message": "Invalid phone number"}), 400
        
        # Clean phone number
        phone = phone.replace(" ", "").replace("-", "")
        if not phone.startswith("+"):
            phone = "+" + phone
        
        login_id = hashlib.md5(f"{phone}{time.time()}".encode()).hexdigest()[:12]
        
        async def do_send_code():
            client = TelegramClient(StringSession(), API_ID, API_HASH)
            await client.connect()
            
            result = await client.send_code_request(phone)
            
            return {
                "client": client,
                "phone": phone,
                "phone_code_hash": result.phone_code_hash,
                "created_at": time.time()
            }
        
        result = run_async(do_send_code())
        
        # Store pending login
        pending_logins[login_id] = result
        
        # Auto-cleanup after 5 minutes
        def cleanup():
            time.sleep(300)
            if login_id in pending_logins:
                try:
                    cl = pending_logins[login_id]["client"]
                    run_async(cl.disconnect())
                except: pass
                del pending_logins[login_id]
        
        t = threading.Thread(target=cleanup, daemon=True)
        t.start()
        
        return jsonify({
            "status": "ok",
            "login_id": login_id,
            "message": f"Code sent to {phone}"
        })
    
    except Exception as e:
        logging.error(f"Extract start error: {e}")
        msg = str(e)
        if "PHONE_NUMBER_INVALID" in msg:
            return jsonify({"status": "error", "message": "Invalid phone number format"}), 400
        if "FLOOD" in msg:
            return jsonify({"status": "error", "message": "Too many attempts. Wait a few minutes."}), 429
        return jsonify({"status": "error", "message": msg}), 500

# =============================================
# 2. EXTRACT SESSION — Step 2: Verify Code
# =============================================
@app.route("/extract_verify", methods=["POST"])
def extract_verify():
    """
    Admin sends the OTP code → we complete login → return session string.
    
    POST: {"login_id": "xyz789", "code": "12345", "password": "4321", "secret": "..."}
    Returns: {"status": "ok", "session": "1BVts...", "phone": "919876543210", "name": "User"}
    """
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403
        
        login_id = data.get("login_id", "")
        code = str(data.get("code", "")).strip()
        password = data.get("password", "")
        
        if login_id not in pending_logins:
            return jsonify({"status": "error", "message": "Login expired. Start again."}), 404
        
        if not code:
            return jsonify({"status": "error", "message": "Code is required"}), 400
        
        login_data = pending_logins[login_id]
        client = login_data["client"]
        phone = login_data["phone"]
        phone_code_hash = login_data["phone_code_hash"]
        
        async def do_verify():
            try:
                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
            except Exception as e:
                if "SESSION_PASSWORD_NEEDED" in str(e):
                    if password:
                        await client.sign_in(password=password)
                    else:
                        raise Exception("2FA_NEEDED")
                else:
                    raise
            
            me = await client.get_me()
            session_str = client.session.save()
            
            phone_num = me.phone or "Unknown"
            name = me.first_name or "Unknown"
            user_id = me.id
            
            await client.disconnect()
            
            return {
                "session": session_str,
                "phone": phone_num,
                "name": name,
                "user_id": user_id
            }
        
        result = run_async(do_verify())
        
        # Clean up pending login
        if login_id in pending_logins:
            del pending_logins[login_id]
        
        return jsonify({
            "status": "ok",
            "session": result["session"],
            "phone": result["phone"],
            "name": result["name"],
            "user_id": result["user_id"]
        })
    
    except Exception as e:
        msg = str(e)
        logging.error(f"Extract verify error: {msg}")
        if "2FA_NEEDED" in msg:
            return jsonify({"status": "2fa", "message": "This account has 2FA. Send the password too."}), 200
        if "PHONE_CODE_INVALID" in msg:
            return jsonify({"status": "error", "message": "Wrong code. Try again."}), 400
        if "PHONE_CODE_EXPIRED" in msg:
            return jsonify({"status": "error", "message": "Code expired. Start again."}), 400
        return jsonify({"status": "error", "message": msg}), 500

# =============================================
# 3. ACTIVATE SESSION — Connect & Get Account Info
# =============================================
@app.route("/activate", methods=["POST"])
def activate_session():
    """
    Connect to Telegram using session string, return phone + name.
    
    POST: {"session": "1BVts...", "secret": "..."}
    Returns: {"status": "ok", "phone": "918899257952", "name": "Pranjal", "session_hash": "abc123"}
    """
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403
        
        session_str = data.get("session", "").strip()
        if not session_str or len(session_str) < 50:
            return jsonify({"status": "error", "message": "Invalid session"}), 400
        
        session_hash = get_session_hash(session_str)
        
        # Check if already active
        if session_hash in active_sessions:
            info = active_sessions[session_hash]
            return jsonify({
                "status": "ok",
                "phone": info["phone"],
                "name": info["name"],
                "user_id": info["user_id"],
                "session_hash": session_hash
            })
        
        async def do_activate():
            client = TelegramClient(StringSession(session_str), API_ID, API_HASH)
            await client.connect()
            if not await client.is_user_authorized():
                await client.disconnect()
                return None
            me = await client.get_me()
            return {
                "client": client,
                "phone": me.phone or "Unknown",
                "name": me.first_name or "Unknown",
                "user_id": me.id,
                "activated_at": time.time()
            }
        
        result = run_async(do_activate())
        
        if not result:
            return jsonify({"status": "error", "message": "Session expired or invalid"}), 400
        
        active_sessions[session_hash] = result
        
        # Auto-disconnect after 10 min
        def cleanup():
            time.sleep(600)
            if session_hash in active_sessions:
                try:
                    cl = active_sessions[session_hash]["client"]
                    run_async(cl.disconnect())
                except: pass
                del active_sessions[session_hash]
        
        t = threading.Thread(target=cleanup, daemon=True)
        t.start()
        
        return jsonify({
            "status": "ok",
            "phone": result["phone"],
            "name": result["name"],
            "user_id": result["user_id"],
            "session_hash": session_hash
        })
    
    except Exception as e:
        logging.error(f"Activate error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================
# 4. GET OTP — Read Messages from Active Session
# =============================================
@app.route("/get_otp", methods=["POST"])
def get_otp():
    """
    Read recent OTP codes from an active session.
    
    POST: {"session_hash": "abc123", "secret": "..."}
    Returns: {"status": "ok", "otp": "89934", "phone": "918899257952"}
    """
    try:
        data = request.get_json()
        if not data or data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error", "message": "Invalid secret"}), 403
        
        session_hash = data.get("session_hash", "")
        if session_hash not in active_sessions:
            return jsonify({"status": "error", "message": "Session not active or expired"}), 404
        
        info = active_sessions[session_hash]
        client = info["client"]
        
        async def do_read():
            otps_found = []
            try:
                # Read messages from all recent chats
                async for dialog in client.iter_dialogs(limit=5):
                    try:
                        msgs = await client.get_messages(dialog, limit=5)
                        for m in msgs:
                            if m.text:
                                codes = re.findall(r'\b(\d{4,6})\b', m.text)
                                for code in codes:
                                    msg_time = m.date.timestamp()
                                    if time.time() - msg_time < 600:
                                        otps_found.append({
                                            "code": code,
                                            "text": m.text[:100],
                                            "time": int(msg_time)
                                        })
                    except: pass
            except: pass
            return otps_found
        
        otps = run_async(do_read())
        
        if otps:
            return jsonify({
                "status": "ok",
                "otp": otps[-1]["code"],
                "full_message": otps[-1]["text"],
                "all_otps": [o["code"] for o in otps],
                "phone": info["phone"]
            })
        else:
            return jsonify({
                "status": "waiting",
                "message": "No OTP found yet",
                "phone": info["phone"]
            })
    
    except Exception as e:
        logging.error(f"OTP error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# =============================================
# 5. DISCONNECT SESSION
# =============================================
@app.route("/disconnect", methods=["POST"])
def disconnect_session():
    try:
        data = request.get_json()
        if data.get("secret") != SECRET_KEY:
            return jsonify({"status": "error"}), 403
        session_hash = data.get("session_hash", "")
        if session_hash in active_sessions:
            try:
                cl = active_sessions[session_hash]["client"]
                run_async(cl.disconnect())
            except: pass
            del active_sessions[session_hash]
        return jsonify({"status": "ok"})
    except:
        return jsonify({"status": "error"}), 500

if __name__ == "__main__":
    print("🚀 Session API v2 starting...")
    print(f"📡 Port: {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
