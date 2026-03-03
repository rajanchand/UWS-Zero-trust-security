"""
Zero Trust Engine - risk scoring and adaptive auth logic.
Risk score runs 0 to 100:
  0-30  low,  31-60 medium,  61-85 high,  86+ critical (blocks login)
"""

from datetime import datetime, timezone
from math import radians, sin, cos, sqrt, atan2

from app.database import get_supabase

# simulated geo-IP lookup table (demo purposes)
_GEO_TABLE = {
    "127.0.0.1": {"country": "Local", "city": "Localhost", "lat": 0.0, "lon": 0.0},
    "192.168.": {"country": "UK", "city": "Private", "lat": 55.86, "lon": -4.25},
    "10.": {"country": "UK", "city": "Private", "lat": 55.86, "lon": -4.25},
    "172.": {"country": "UK", "city": "Private", "lat": 55.86, "lon": -4.25},
}

_COUNTRY_DB = {
    "1.": {"country": "AU", "city": "Sydney", "lat": -33.87, "lon": 151.21},
    "2.": {"country": "EU", "city": "Amsterdam", "lat": 52.37, "lon": 4.90},
    "5.": {"country": "RU", "city": "Moscow", "lat": 55.76, "lon": 37.62},
    "8.": {"country": "US", "city": "LA", "lat": 34.05, "lon": -118.24},
    "41.": {"country": "NG", "city": "Lagos", "lat": 6.52, "lon": 3.38},
    "103.": {"country": "IN", "city": "Mumbai", "lat": 19.08, "lon": 72.88},
    "185.": {"country": "DE", "city": "Berlin", "lat": 52.52, "lon": 13.41},
}


def geolocate_ip(ip: str) -> dict:
    """Simulated geo-IP lookup for the demo."""
    for prefix, info in _GEO_TABLE.items():
        if ip.startswith(prefix):
            return info
    for prefix, info in _COUNTRY_DB.items():
        if ip.startswith(prefix):
            return info
    return {"country": "UK", "city": "London", "lat": 51.51, "lon": -0.13}


def _haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on earth (km)."""
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


# VPN detection (simplified for demo)
_VPN_RANGES = ["185.", "104."]


def is_vpn(ip: str) -> bool:
    return any(ip.startswith(p) for p in _VPN_RANGES)


# impossible travel check

def impossible_travel(user_id: str, current_ip: str):
    """Check if user moved faster than physically possible. Returns (flag, distance_km)."""
    db = get_supabase()
    last = (
        db.table("audit_logs")
        .select("ip_address, created_at")
        .eq("user_id", user_id)
        .eq("action", "login_success")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if not last.data:
        return False, 0.0
    prev = last.data[0]
    prev_geo = geolocate_ip(prev["ip_address"])
    cur_geo = geolocate_ip(current_ip)
    dist = _haversine_km(prev_geo["lat"], prev_geo["lon"], cur_geo["lat"], cur_geo["lon"])
    ts = prev["created_at"]
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    hours = max((datetime.now(timezone.utc) - ts).total_seconds() / 3600, 0.01)
    speed_kmh = dist / hours
    return speed_kmh > 900, dist


# risk scoring

def calculate_risk(user_id, ip, fingerprint, failed_attempts=0):
    """Compute a risk score dict: {score, level, factors, country, city}"""
    score = 0
    factors = []

    # 1) unknown device?
    db = get_supabase()
    dev = (
        db.table("trusted_devices")
        .select("is_trusted")
        .eq("user_id", user_id)
        .eq("fingerprint", fingerprint)
        .limit(1)
        .execute()
    )
    if not dev.data:
        score += 25
        factors.append("Unknown device")
    elif not dev.data[0]["is_trusted"]:
        score += 15
        factors.append("Unverified device")

    # 2) VPN
    if is_vpn(ip):
        score += 20
        factors.append("VPN detected")

    # 3) impossible travel
    travel, dist = impossible_travel(user_id, ip)
    if travel:
        score += 30
        factors.append(f"Impossible travel ({dist:.0f} km)")

    # 4) failed login attempts
    if failed_attempts >= 3:
        score += 15
        factors.append(f"{failed_attempts} failed attempts")
    elif failed_attempts >= 1:
        score += 5
        factors.append(f"{failed_attempts} failed attempt(s)")

    # 5) country risk
    geo = geolocate_ip(ip)
    high_risk_countries = ["RU", "NG"]
    if geo["country"] in high_risk_countries:
        score += 20
        factors.append(f"High-risk country: {geo['country']}")

    # work out risk level
    if score <= 30:
        level = "low"
    elif score <= 60:
        level = "medium"
    elif score <= 85:
        level = "high"
    else:
        level = "critical"

    return {
        "score": min(score, 100),
        "level": level,
        "factors": factors,
        "country": geo["country"],
        "city": geo["city"],
    }


# device registration

def register_device(user_id, fingerprint, browser, os_name, ip, location,
                    risk_level="medium", trusted=False):
    """Upsert a device record. Updates last_seen if it already exists."""
    db = get_supabase()
    existing = (
        db.table("trusted_devices")
        .select("id")
        .eq("user_id", user_id)
        .eq("fingerprint", fingerprint)
        .limit(1)
        .execute()
    )
    now = datetime.now(timezone.utc).isoformat()
    if existing.data:
        db.table("trusted_devices").update({
            "last_seen": now,
            "ip_address": ip,
            "location": location,
            "risk_level": risk_level,
        }).eq("id", existing.data[0]["id"]).execute()
    else:
        db.table("trusted_devices").insert({
            "user_id": user_id,
            "fingerprint": fingerprint,
            "browser": browser,
            "os": os_name,
            "ip_address": ip,
            "location": location,
            "is_trusted": trusted,
            "risk_level": risk_level,
        }).execute()
