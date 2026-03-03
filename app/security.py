"""Security helpers - password hashing, OTP, sessions, audit logging."""

import secrets
import string
import hashlib
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

import bcrypt

from app.config import settings
from app.database import get_supabase


# password hashing

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# OTP generation and verification

def generate_otp(length: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def store_otp(user_id: str, otp_code: str) -> None:
    db = get_supabase()
    expires = datetime.now(timezone.utc) + timedelta(seconds=settings.OTP_EXPIRY_SECONDS)
    db.table("otp_tokens").update({"used": True}).eq("user_id", user_id).eq("used", False).execute()
    db.table("otp_tokens").insert({
        "user_id": user_id,
        "otp_code": otp_code,
        "expires_at": expires.isoformat(),
    }).execute()


def verify_otp(user_id: str, otp_code: str) -> bool:
    db = get_supabase()
    now = datetime.now(timezone.utc).isoformat()
    res = (
        db.table("otp_tokens")
        .select("id")
        .eq("user_id", user_id)
        .eq("otp_code", otp_code)
        .eq("used", False)
        .gte("expires_at", now)
        .limit(1)
        .execute()
    )
    if res.data:
        db.table("otp_tokens").update({"used": True}).eq("id", res.data[0]["id"]).execute()
        return True
    return False


def send_otp_email(email: str, otp_code: str) -> bool:
    """Try sending OTP via SMTP. Returns False if not configured (demo mode)."""
    if not settings.SMTP_HOST:
        return False
    try:
        msg = MIMEText(f"Your ZTS verification code is: {otp_code}\nValid for {settings.OTP_EXPIRY_SECONDS // 60} minutes.")
        msg["Subject"] = "ZTS – Your One-Time Password"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = email
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as srv:
            srv.starttls()
            srv.login(settings.SMTP_USER, settings.SMTP_PASS)
            srv.send_message(msg)
        return True
    except Exception:
        return False


# sessions

def create_session(user_id: str, ip: str, ua: str, fingerprint: str) -> str:
    db = get_supabase()
    token = secrets.token_urlsafe(48)
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
    db.table("sessions").insert({
        "user_id": user_id,
        "token": token,
        "ip_address": ip,
        "user_agent": ua,
        "device_fingerprint": fingerprint,
        "expires_at": expires.isoformat(),
    }).execute()
    return token


def validate_session(token: str) -> dict | None:
    """Return session row if valid, else None. Also slides the expiry window."""
    db = get_supabase()
    now = datetime.now(timezone.utc)
    res = (
        db.table("sessions")
        .select("*")
        .eq("token", token)
        .gte("expires_at", now.isoformat())
        .limit(1)
        .execute()
    )
    if not res.data:
        return None
    session = res.data[0]
    # slide the expiry window forward
    new_expires = now + timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
    db.table("sessions").update({
        "last_active": now.isoformat(),
        "expires_at": new_expires.isoformat(),
    }).eq("id", session["id"]).execute()
    return session


def destroy_session(token: str) -> None:
    db = get_supabase()
    db.table("sessions").delete().eq("token", token).execute()


# account locking

def increment_failed(user_id: str) -> int:
    db = get_supabase()
    user = db.table("users").select("failed_attempts").eq("id", user_id).single().execute()
    attempts = (user.data.get("failed_attempts") or 0) + 1
    update: dict = {"failed_attempts": attempts}
    if attempts >= settings.MAX_FAILED_ATTEMPTS:
        update["locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    db.table("users").update(update).eq("id", user_id).execute()
    return attempts


def reset_failed(user_id: str) -> None:
    db = get_supabase()
    db.table("users").update({"failed_attempts": 0, "locked_until": None}).eq("id", user_id).execute()


def is_locked(user: dict) -> bool:
    locked = user.get("locked_until")
    if not locked:
        return False
    if isinstance(locked, str):
        locked = datetime.fromisoformat(locked.replace("Z", "+00:00"))
    return locked > datetime.now(timezone.utc)


# device fingerprinting

def device_hash(ua: str, ip: str, extra: str = "") -> str:
    raw = f"{ua}|{ip}|{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# audit logging

def audit_log(
    user_id: str | None,
    action: str,
    detail: str = "",
    ip: str = "",
    ua: str = "",
    fingerprint: str = "",
    risk_score: int = 0,
    country: str = "",
) -> None:
    db = get_supabase()
    db.table("audit_logs").insert({
        "user_id": user_id,
        "action": action,
        "detail": detail,
        "ip_address": ip,
        "user_agent": ua,
        "device_fingerprint": fingerprint,
        "risk_score": risk_score,
        "country": country,
    }).execute()
