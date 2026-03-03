"""Dashboard routes - handles RBAC views, admin panel, device mgmt etc."""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from user_agents import parse as parse_ua

from app.database import get_supabase
from app.security import validate_session, destroy_session, hash_password, audit_log
from app.trust_engine import geolocate_ip, calculate_risk

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# role metadata for sidebar & labels
ROLE_DASHBOARDS = {
    "SuperAdmin": {"label": "Super Admin", "color": "#dc2626"},
    "HR": {"label": "Human Resources", "color": "#16a34a"},
    "Finance": {"label": "Finance", "color": "#2563eb"},
    "IT": {"label": "IT Operations", "color": "#9333ea"},
    "CustomerSupport": {"label": "Customer Support", "color": "#d97706"},
}

# department-specific card sections
ROLE_SECTIONS = {
    "HR": [
        {"title": "Employee Records", "desc": "View and manage employee data"},
        {"title": "Leave Requests", "desc": "Approve or reject leave applications"},
        {"title": "Payroll Summary", "desc": "Monthly payroll overview"},
    ],
    "Finance": [
        {"title": "Budget Reports", "desc": "Quarterly financial reports"},
        {"title": "Invoices", "desc": "Manage incoming and outgoing invoices"},
        {"title": "Expense Claims", "desc": "Review submitted expenses"},
    ],
    "IT": [
        {"title": "Server Status", "desc": "Monitor infrastructure health"},
        {"title": "Tickets", "desc": "IT support ticket queue"},
        {"title": "Access Requests", "desc": "Manage access provisioning"},
    ],
    "CustomerSupport": [
        {"title": "Open Tickets", "desc": "Customer issues awaiting response"},
        {"title": "Knowledge Base", "desc": "Internal support articles"},
        {"title": "Feedback", "desc": "Customer satisfaction data"},
    ],
}

DEPARTMENTS = ["SuperAdmin", "HR", "Finance", "IT", "CustomerSupport"]

def _client_ip(request: Request) -> str:
    """Extract real client IP, checking x-forwarded-for first."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


async def _get_current_user(request: Request) -> dict | None:
    """Pull the session token from cookie, query param, or header and load the user."""
    token = (
        request.cookies.get("zts_session")
        or request.query_params.get("s", "")
        or request.headers.get("x-session-token", "")
    )
    if not token:
        return None
    session = validate_session(token)
    if not session:
        return None
    db = get_supabase()
    user = db.table("users").select("*").eq("id", session["user_id"]).single().execute()
    if not user.data:
        return None
    user.data["_session"] = session
    user.data["_token"] = token
    return user.data


def _base_ctx(request, user, page="dashboard"):
    """Build the common template context dict shared across pages."""
    role = user["role"]
    return {
        "request": request,
        "user": user,
        "token": user.get("_token", ""),
        "role_meta": ROLE_DASHBOARDS.get(role, {}),
        "is_superadmin": role == "SuperAdmin",
        "active_page": page,
    }


# ---------- page routes ----------

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = await _get_current_user(request)
    if not user:
        return RedirectResponse("/login?error=Session+expired", status_code=302)

    ip = _client_ip(request)
    ua_string = request.headers.get("user-agent", "")
    ua = parse_ua(ua_string)
    geo = geolocate_ip(ip)
    fingerprint = user["_session"].get("device_fingerprint", "")

    risk = calculate_risk(user["id"], ip, fingerprint, user.get("failed_attempts", 0))

    db = get_supabase()

    role = user["role"]

    if role == "SuperAdmin":
        sections = []
        for r, cards in ROLE_SECTIONS.items():
            sections.append({"role": r, "cards": cards, "meta": ROLE_DASHBOARDS[r]})
    else:
        sections = [{"role": role, "cards": ROLE_SECTIONS.get(role, []), "meta": ROLE_DASHBOARDS.get(role, {})}]

    # Last login time
    last_login = db.table("audit_logs").select("created_at").eq("user_id", user["id"]).eq("action", "login_success").order("created_at", desc=True).limit(2).execute()
    last_login_time = last_login.data[1]["created_at"][:16] if last_login.data and len(last_login.data) > 1 else "First login"

    # SuperAdmin stats
    stats = {}
    if role == "SuperAdmin":
        all_users = db.table("users").select("id, is_active, role").execute()
        active_sessions = db.table("sessions").select("id").gte("expires_at", datetime.now(timezone.utc).isoformat()).execute()
        high_risk_logs = db.table("audit_logs").select("id").gte("risk_score", 60).execute()

        seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        recent_logins = db.table("audit_logs").select("action, created_at").in_("action", ["login_success", "login_fail"]).gte("created_at", seven_days_ago).order("created_at").execute()

        login_chart = {}
        for log in (recent_logins.data or []):
            day = log["created_at"][:10]
            if day not in login_chart:
                login_chart[day] = {"success": 0, "fail": 0}
            if log["action"] == "login_success":
                login_chart[day]["success"] += 1
            else:
                login_chart[day]["fail"] += 1

        chart_labels = sorted(login_chart.keys())
        chart_success = [login_chart[d]["success"] for d in chart_labels]
        chart_fail = [login_chart[d]["fail"] for d in chart_labels]

        all_risk_logs = db.table("audit_logs").select("risk_score").gte("created_at", seven_days_ago).execute()
        risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for r in (all_risk_logs.data or []):
            score = r.get("risk_score", 0) or 0
            if score < 30:
                risk_dist["low"] += 1
            elif score < 60:
                risk_dist["medium"] += 1
            elif score < 85:
                risk_dist["high"] += 1
            else:
                risk_dist["critical"] += 1

        stats = {
            "total_users": len(all_users.data or []),
            "active_sessions": len(active_sessions.data or []),
            "high_risk_count": len(high_risk_logs.data or []),
            "chart_labels": chart_labels,
            "chart_success": chart_success,
            "chart_fail": chart_fail,
            "risk_dist": risk_dist,
        }

    # Offline users (total - active sessions)
    offline_users = 0
    if role == "SuperAdmin" and stats:
        offline_users = stats["total_users"] - stats["active_sessions"]
        if offline_users < 0:
            offline_users = 0

    ctx = _base_ctx(request, user, "dashboard")
    ctx.update({
        "sections": sections,
        "risk": risk,
        "geo": geo,
        "browser": f"{ua.browser.family} {ua.browser.version_string}",
        "os_name": f"{ua.os.family} {ua.os.version_string}",
        "ip": ip,
        "last_login_time": last_login_time,
        "stats": stats,
        "offline_users": offline_users,
    })
    return templates.TemplateResponse("dashboard.html", ctx)


# security overview page

@router.get("/security", response_class=HTMLResponse)
async def security_page(request: Request):
    user = await _get_current_user(request)
    if not user:
        return RedirectResponse("/login?error=Session+expired", status_code=302)

    ip = _client_ip(request)
    ua_string = request.headers.get("user-agent", "")
    ua = parse_ua(ua_string)
    geo = geolocate_ip(ip)
    fingerprint = user["_session"].get("device_fingerprint", "")

    risk = calculate_risk(user["id"], ip, fingerprint, user.get("failed_attempts", 0))

    db = get_supabase()

    # Security alerts
    alerts_res = db.table("audit_logs").select("action, detail, created_at, ip_address").eq("user_id", user["id"]).in_("action", ["login_fail", "login_blocked", "otp_fail"]).order("created_at", desc=True).limit(5).execute()
    security_alerts = alerts_res.data or []

    # IP Allow / Block list (SuperAdmin only)
    ip_list = []
    if user["role"] == "SuperAdmin":
        all_logs = db.table("audit_logs").select("ip_address, action, risk_score, created_at").order("created_at", desc=True).limit(500).execute()
        ip_map = {}
        for entry in (all_logs.data or []):
            addr = entry.get("ip_address")
            if not addr or addr in ip_map:
                continue
            rs = entry.get("risk_score", 0) or 0
            status = "blocked" if rs >= 60 or entry["action"] in ("login_blocked",) else "allowed"
            ip_map[addr] = {
                "ip": addr,
                "status": status,
                "risk_score": rs,
                "last_seen": entry["created_at"][:16] if entry.get("created_at") else "—",
            }
        ip_list = list(ip_map.values())

    ctx = _base_ctx(request, user, "security")
    ctx.update({
        "risk": risk,
        "geo": geo,
        "browser": f"{ua.browser.family} {ua.browser.version_string}",
        "os_name": f"{ua.os.family} {ua.os.version_string}",
        "ip": ip,
        "security_alerts": security_alerts,
        "ip_list": ip_list,
    })
    return templates.TemplateResponse("security.html", ctx)


# devices page

@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    user = await _get_current_user(request)
    if not user:
        return RedirectResponse("/login?error=Session+expired", status_code=302)

    db = get_supabase()

    if user["role"] == "SuperAdmin":
        # SuperAdmin sees all devices joined with user info
        all_devices = db.table("trusted_devices").select("*, users(username, email, role)").order("last_seen", desc=True).execute()
    else:
        all_devices = db.table("trusted_devices").select("*, users(username, email, role)").eq("user_id", user["id"]).order("last_seen", desc=True).execute()

    # Build enriched device list
    devices = []
    for d in (all_devices.data or []):
        u_info = d.get("users") or {}
        devices.append({
            "id": d["id"],
            "username": u_info.get("username", "—"),
            "device_name": f"{d.get('browser', '—')} on {d.get('os', '—')}",
            "status": "Online" if d.get("is_trusted") else "Offline",
            "browser": d.get("browser", "—"),
            "os": d.get("os", "—"),
            "ip_address": d.get("ip_address", "—"),
            "last_seen": d.get("last_seen", "")[:16] if d.get("last_seen") else "—",
            "is_trusted": d.get("is_trusted", False),
            "approved_by": "Admin" if d.get("is_trusted") else "Pending",
            "mac_address": d.get("fingerprint", "—")[:17] if d.get("fingerprint") else "—",
            "location": d.get("location", "—"),
            "risk_level": d.get("risk_level", "medium"),
            "user_id": d.get("user_id"),
        })

    ctx = _base_ctx(request, user, "devices")
    ctx["devices"] = devices
    return templates.TemplateResponse("devices.html", ctx)


@router.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return RedirectResponse("/dashboard", status_code=302)
    db = get_supabase()
    logs = db.table("audit_logs").select("*, users(username)").order("created_at", desc=True).limit(200).execute()
    ctx = _base_ctx(request, user, "logs")
    ctx["logs"] = logs.data or []
    return templates.TemplateResponse("admin_logs.html", ctx)


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return RedirectResponse("/dashboard", status_code=302)
    db = get_supabase()
    users = db.table("users").select("*").order("created_at").execute()

    sessions = db.table("sessions").select("user_id").gte("expires_at", datetime.now(timezone.utc).isoformat()).execute()
    session_counts = {}
    for s in (sessions.data or []):
        uid = s["user_id"]
        session_counts[uid] = session_counts.get(uid, 0) + 1

    logs = db.table("audit_logs").select("user_id, created_at, ip_address").eq("action", "login_success").order("created_at", desc=True).execute()
    last_logins = {}
    for lg in (logs.data or []):
        uid = lg["user_id"]
        if uid not in last_logins:
            last_logins[uid] = lg

    all_devices = db.table("trusted_devices").select("user_id, browser, os, ip_address, is_trusted").execute()
    user_devices = {}
    for d in (all_devices.data or []):
        uid = d["user_id"]
        if uid not in user_devices:
            user_devices[uid] = []
        user_devices[uid].append(d)

    ctx = _base_ctx(request, user, "users")
    ctx.update({
        "all_users": users.data or [],
        "session_counts": session_counts,
        "last_logins": last_logins,
        "user_devices": user_devices,
        "departments": DEPARTMENTS,
    })
    return templates.TemplateResponse("admin_users.html", ctx)


# ---------- API endpoints ----------

@router.post("/api/device/trust")
async def trust_device(request: Request):
    user = await _get_current_user(request)
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    device_id = body.get("device_id")
    trust = body.get("trust", True)
    db = get_supabase()
    query = db.table("trusted_devices").update({
        "is_trusted": trust,
        "risk_level": "low" if trust else "high",
    }).eq("id", device_id)
    if user["role"] != "SuperAdmin":
        query = query.eq("user_id", user["id"])
    query.execute()
    audit_log(user["id"], "device_trust_toggle", f"device={device_id} trusted={trust}", _client_ip(request))
    return JSONResponse({"ok": True})


@router.post("/api/heartbeat")
async def heartbeat(request: Request):
    user = await _get_current_user(request)
    if not user:
        return JSONResponse({"expired": True}, status_code=401)
    return JSONResponse({"expired": False})


@router.post("/api/admin/unlock")
async def unlock_user(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    target_id = body.get("user_id")
    db = get_supabase()
    db.table("users").update({"failed_attempts": 0, "locked_until": None}).eq("id", target_id).execute()
    audit_log(user["id"], "admin_unlock", f"Unlocked user {target_id}", _client_ip(request))
    return JSONResponse({"ok": True})


@router.post("/api/admin/create-user")
async def create_user(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    username = body.get("username", "").strip()
    email = body.get("email", "").strip()
    password = body.get("password", "").strip()
    role = body.get("role", "CustomerSupport")
    if not username or not email or not password:
        return JSONResponse({"error": "Username, email, and password are required"}, status_code=400)
    if role not in DEPARTMENTS:
        return JSONResponse({"error": f"Invalid role: {role}"}, status_code=400)
    db = get_supabase()
    existing = db.table("users").select("id").eq("username", username).execute()
    if existing.data:
        return JSONResponse({"error": "Username already exists"}, status_code=400)
    pw_hash = hash_password(password)
    db.table("users").insert({
        "username": username,
        "email": email,
        "password_hash": pw_hash,
        "role": role,
    }).execute()
    audit_log(user["id"], "admin_create_user", f"Created user {username} ({role})", _client_ip(request))
    return JSONResponse({"ok": True, "message": f"User {username} created"})


@router.post("/api/admin/delete-user")
async def delete_user(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    target_id = body.get("user_id")
    if target_id == user["id"]:
        return JSONResponse({"error": "Cannot delete yourself"}, status_code=400)
    db = get_supabase()
    db.table("sessions").delete().eq("user_id", target_id).execute()
    db.table("trusted_devices").delete().eq("user_id", target_id).execute()
    db.table("otp_tokens").delete().eq("user_id", target_id).execute()
    db.table("users").delete().eq("id", target_id).execute()
    audit_log(user["id"], "admin_delete_user", f"Deleted user {target_id}", _client_ip(request))
    return JSONResponse({"ok": True})


@router.post("/api/admin/assign-role")
async def assign_role(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    target_id = body.get("user_id")
    new_role = body.get("role")
    if new_role not in DEPARTMENTS:
        return JSONResponse({"error": f"Invalid role: {new_role}"}, status_code=400)
    db = get_supabase()
    db.table("users").update({"role": new_role}).eq("id", target_id).execute()
    audit_log(user["id"], "admin_assign_role", f"User {target_id} -> {new_role}", _client_ip(request))
    return JSONResponse({"ok": True})


@router.post("/api/admin/toggle-user")
async def toggle_user(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    target_id = body.get("user_id")
    enable = body.get("enable", True)
    if target_id == user["id"]:
        return JSONResponse({"error": "Cannot disable yourself"}, status_code=400)
    db = get_supabase()
    db.table("users").update({"is_active": enable}).eq("id", target_id).execute()
    if not enable:
        db.table("sessions").delete().eq("user_id", target_id).execute()
    action = "admin_enable_user" if enable else "admin_disable_user"
    audit_log(user["id"], action, f"User {target_id} active={enable}", _client_ip(request))
    return JSONResponse({"ok": True})


@router.post("/api/admin/force-logout")
async def force_logout(request: Request):
    user = await _get_current_user(request)
    if not user or user["role"] != "SuperAdmin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    body = await request.json()
    target_id = body.get("user_id")
    db = get_supabase()
    db.table("sessions").delete().eq("user_id", target_id).execute()
    audit_log(user["id"], "admin_force_logout", f"Force-logged-out user {target_id}", _client_ip(request))
    return JSONResponse({"ok": True})
