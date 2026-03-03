"""Auth routes - login, OTP verification, logout."""

from fastapi import APIRouter, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from user_agents import parse as parse_ua
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.database import get_supabase
from app.config import settings
from app.security import (
    verify_password, generate_otp, store_otp, verify_otp,
    send_otp_email, create_session, destroy_session,
    increment_failed, reset_failed, is_locked, audit_log,
)
from app.trust_engine import geolocate_ip, calculate_risk, register_device

_signer = URLSafeTimedSerializer(settings.SECRET_KEY)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    fingerprint: str = Form(""),
):
    db = get_supabase()
    ip = _client_ip(request)
    ua_string = request.headers.get("user-agent", "")
    ua = parse_ua(ua_string)

    # look up user
    res = db.table("users").select("*").eq("username", username).limit(1).execute()
    if not res.data:
        audit_log(None, "login_fail", f"Unknown user: {username}", ip, ua_string, fingerprint)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password.",
        })

    user = res.data[0]

    # account locked?
    if is_locked(user):
        audit_log(user["id"], "login_blocked", "Account locked", ip, ua_string, fingerprint)
        return templates.TemplateResponse("locked.html", {"request": request, "username": username})

    # password check
    if not verify_password(password, user["password_hash"]):
        attempts = increment_failed(user["id"])
        remaining = max(settings.MAX_FAILED_ATTEMPTS - attempts, 0)
        audit_log(user["id"], "login_fail", f"Wrong password (attempt {attempts})", ip, ua_string, fingerprint)
        if attempts >= settings.MAX_FAILED_ATTEMPTS:
            return templates.TemplateResponse("locked.html", {"request": request, "username": username})
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"Invalid username or password. {remaining} attempt(s) remaining.",
        })

    # risk assessment
    risk = calculate_risk(user["id"], ip, fingerprint, user.get("failed_attempts", 0))

    if risk["level"] == "critical":
        audit_log(user["id"], "login_blocked", f"Risk critical: {risk['factors']}", ip, ua_string, fingerprint, risk["score"], risk["country"])
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Login blocked due to high-risk signals. Contact your administrator.",
        })

    # register / update device record
    geo = geolocate_ip(ip)
    register_device(
        user_id=user["id"],
        fingerprint=fingerprint or f"fp-{ip}",
        browser=f"{ua.browser.family} {ua.browser.version_string}",
        os_name=f"{ua.os.family} {ua.os.version_string}",
        ip=ip,
        location=f"{geo['city']}, {geo['country']}",
        risk_level=risk["level"],
    )

    # generate & send OTP
    otp = generate_otp()
    store_otp(user["id"], otp)
    sent = send_otp_email(user["email"], otp)

    audit_log(user["id"], "otp_sent", f"OTP generated (email_sent={sent})", ip, ua_string, fingerprint, risk["score"], risk["country"])

    # signed token carrying user_id + fingerprint for the OTP form
    pending_token = _signer.dumps({"uid": user["id"], "fp": fingerprint or f"fp-{ip}"})

    response = templates.TemplateResponse("otp.html", {
        "request": request,
        "username": username,
        "email_hint": user["email"][:3] + "***" + user["email"][user["email"].index("@"):],
        "otp_display": otp if not sent else None,  # show OTP on screen only if email not configured
        "risk": risk,
        "pending_token": pending_token,
    })
    return response


@router.post("/verify-otp")
async def verify_otp_submit(
    request: Request,
    otp_code: str = Form(...),
    pending_token: str = Form(""),
):
    ip = _client_ip(request)
    ua_string = request.headers.get("user-agent", "")

    # decode signed token (valid for 10 min)
    try:
        data = _signer.loads(pending_token, max_age=600)
        user_id = data["uid"]
        fingerprint = data.get("fp", "")
    except (BadSignature, SignatureExpired, KeyError):
        return RedirectResponse("/login?error=Session+expired.+Please+login+again.", status_code=302)

    if not verify_otp(user_id, otp_code):
        attempts = increment_failed(user_id)
        audit_log(user_id, "otp_fail", f"Wrong OTP (attempt {attempts})", ip, ua_string, fingerprint)

        db = get_supabase()
        user = db.table("users").select("email, failed_attempts").eq("id", user_id).single().execute()
        u = user.data
        if attempts >= settings.MAX_FAILED_ATTEMPTS:
            return templates.TemplateResponse("locked.html", {"request": request, "username": ""})
        return templates.TemplateResponse("otp.html", {
            "request": request,
            "username": "",
            "email_hint": "",
            "otp_display": None,
            "risk": {"score": 0, "level": "medium", "factors": []},
            "pending_token": pending_token,
            "error": f"Invalid OTP. {max(settings.MAX_FAILED_ATTEMPTS - attempts, 0)} attempt(s) remaining.",
        })

    # success - create session
    reset_failed(user_id)
    token = create_session(user_id, ip, ua_string, fingerprint)

    audit_log(user_id, "login_success", "MFA complete", ip, ua_string, fingerprint)

    # redirect via /auth-callback so JS can store the token in localStorage
    response = RedirectResponse(f"/auth-callback?t={token}", status_code=302)
    return response


@router.get("/auth-callback", response_class=HTMLResponse)
async def auth_callback(request: Request, t: str = ""):
    """Renders a small page whose JS stores the session token in localStorage
    then navigates to /dashboard. Avoids reliance on cookies."""
    if not t:
        return RedirectResponse("/login?error=Missing+session+token.", status_code=302)
    return templates.TemplateResponse("auth_callback.html", {
        "request": request,
        "token": t,
    })


@router.get("/logout")
async def logout(request: Request):
    token = request.cookies.get("zts_session") or request.query_params.get("s", "")
    if token:
        destroy_session(token)
        ua_string = request.headers.get("user-agent", "")
        ip = _client_ip(request)
        audit_log(None, "logout", "", ip, ua_string)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("zts_session")
    return response
