"""Quick end-to-end test for ZTS."""
import httpx, re, sys

base = "http://localhost:8000"
c = httpx.Client(follow_redirects=False)

# 1. Login
r = c.post(f"{base}/login", data={"username": "superadmin", "password": "Password1!", "fingerprint": "test-fp"})
print(f"1. Login POST: {r.status_code}")
if r.status_code != 200:
    print(f"   ERROR: {r.text[:200]}")
    sys.exit(1)

# 2. Extract OTP
m = re.search(r'class="demo-otp">(\d+)', r.text)
if not m:
    print("   ERROR: No OTP found in response")
    sys.exit(1)
otp = m.group(1)
print(f"   OTP: {otp}")

# 2b. Extract pending_token hidden field
t = re.search(r'name="pending_token"\s+value="([^"]+)"', r.text)
if not t:
    print("   ERROR: No pending_token found in response")
    sys.exit(1)
pending = t.group(1)
print(f"   Pending token: {pending[:20]}…")

# 3. Verify OTP
r2 = c.post(f"{base}/verify-otp", data={"otp_code": otp, "pending_token": pending})
print(f"2. OTP verify: {r2.status_code}")
if r2.status_code == 302:
    loc = r2.headers.get('location','')
    print(f"   Redirect to: {loc}")

# 3b. Follow auth-callback (now returns HTML with JS redirect)
r2b = c.get(f"{base}{loc}" if loc.startswith("/") else loc)
print(f"   Auth callback: {r2b.status_code}")

# 3c. Extract the session token from the JS redirect in auth_callback.html
session_match = re.search(r'var token = "([^"]+)"', r2b.text)
if not session_match:
    print("   ERROR: No session token in auth callback")
    sys.exit(1)
session_token = session_match.group(1)
print(f"   Session token: {session_token[:20]}…")

# 4. Dashboard – use query param ?s= to pass token (same as browser flow)
r3 = c.get(f"{base}/dashboard?s={session_token}")
print(f"3. Dashboard GET: {r3.status_code}")
if r3.status_code == 200:
    print("   ✅ Dashboard loaded successfully!")
    print(f'   Contains "Department Dashboard": {"Department Dashboard" in r3.text}')
    print(f'   Contains "Risk Score": {"Risk Score" in r3.text}')
else:
    print(f"   ❌ Error: {r3.text[:300]}")
